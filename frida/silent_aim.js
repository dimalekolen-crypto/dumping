'use strict';

// frida/silent_aim.js — external silent aim for non-jailbroken iOS.
// frida -U -f <bundle-id> -l frida/silent_aim.js --no-pause
//
// il2cpp MethodInfo->methodPointer hook is useless on stock iOS (W^X, arm64e,
// inline __TEXT patch crashes), so everything runs from Frida: resolve
// ItemEquipWeaponRange.fka via il2cpp exports, Interceptor.attach to its real
// code address, and on each shot bend the (from, to) ray toward the nearest
// enemy head.

const OFF_PLAYER_IS_DEAD = 0xB8;
const OFF_PLAYER_TEAM = 0xBC;
const OFF_PLAYER_CHARACTER = 0xF0;
const OFF_CHAR_MODEL_CONTAINER = 0x120;
const OFF_CHAR_CONTROLLER = 0x130;
const OFF_CTRL_REMOTE_VIS = 0xC8;
const OFF_RV_MODEL = 0x48;
const OFF_MODEL_HEAD = 0x58;
const MAX_SHOT_RANGE = 400.0;

let api = null;

function exportByName(name) {
    let p = null;
    if (Module.findGlobalExportByName) p = Module.findGlobalExportByName(name);
    if (p === null && Module.findExportByName) p = Module.findExportByName(null, name);
    return p;
}
function must(name) {
    const p = exportByName(name);
    if (p === null) throw new Error('missing il2cpp export: ' + name);
    return p;
}
function bindApi() {
    api = {
        domain_get: new NativeFunction(must('il2cpp_domain_get'), 'pointer', []),
        domain_get_assemblies: new NativeFunction(
            must('il2cpp_domain_get_assemblies'), 'pointer', ['pointer', 'pointer']
        ),
        assembly_get_image: new NativeFunction(
            must('il2cpp_assembly_get_image'), 'pointer', ['pointer']
        ),
        class_from_name: new NativeFunction(
            must('il2cpp_class_from_name'), 'pointer', ['pointer', 'pointer', 'pointer']
        ),
        class_get_method_from_name: new NativeFunction(
            must('il2cpp_class_get_method_from_name'), 'pointer', ['pointer', 'pointer', 'int']
        ),
        runtime_invoke: new NativeFunction(
            must('il2cpp_runtime_invoke'), 'pointer', ['pointer', 'pointer', 'pointer', 'pointer']
        ),
        thread_attach: new NativeFunction(must('il2cpp_thread_attach'), 'pointer', ['pointer'])
    };
}
function readPtr(p) { return p.readPointer(); }
function readF32(p) { return p.readFloat(); }
function readVec3At(ptr) {
    return { x: readF32(ptr), y: readF32(ptr.add(4)), z: readF32(ptr.add(8)) };
}
function readVec3Regs(context, start) {
    return { x: context['s' + start], y: context['s' + start + 1], z: context['s' + start + 2] };
}
function writeVec3Regs(context, start, v) {
    context['s' + start] = v.x;
    context['s' + start + 1] = v.y;
    context['s' + start + 2] = v.z;
}
function findClass(ns, name) {
    const domain = api.domain_get();
    const sizePtr = Memory.alloc(4);
    const assemblies = api.domain_get_assemblies(domain, sizePtr);
    const count = sizePtr.readUInt();
    for (let i = 0; i < count; i++) {
        const asm = readPtr(assemblies.add(i * Process.pointerSize));
        const image = api.assembly_get_image(asm);
        if (image.isNull()) continue;
        const k = api.class_from_name(image, ns, name);
        if (!k.isNull()) return k;
    }
    return null;
}

function getTransformPosition(transformPtr) {
    if (transformPtr.isNull()) return null;
    const domain = api.domain_get();
    const sizePtr = Memory.alloc(4);
    const assemblies = api.domain_get_assemblies(domain, sizePtr);
    const count = sizePtr.readUInt();
    let tGetPosMI = null;
    for (let i = 0; i < count && tGetPosMI === null; i++) {
        const asm = readPtr(assemblies.add(i * Process.pointerSize));
        const img = api.assembly_get_image(asm);
        const tKlass = api.class_from_name(img, '', 'Transform');
        if (!tKlass.isNull()) {
            tGetPosMI = api.class_get_method_from_name(tKlass, 'get_position', 0);
        }
    }
    if (tGetPosMI === null) return null;
    const excPtr = Memory.alloc(Process.pointerSize);
    const ret = api.runtime_invoke(tGetPosMI, transformPtr, null, excPtr);
    if (ret.isNull()) return null;
    return readVec3At(ret);
}

function getHeadPosition(characterPtr) {
    if (characterPtr.isNull()) return null;
    const modelContainer = readPtr(characterPtr.add(OFF_CHAR_MODEL_CONTAINER));
    if (modelContainer.isNull()) return null;
    const ctrl = readPtr(characterPtr.add(OFF_CHAR_CONTROLLER));
    if (ctrl.isNull()) return null;
    const rv = readPtr(ctrl.add(OFF_CTRL_REMOTE_VIS));
    if (rv.isNull()) return null;
    const model = readPtr(rv.add(OFF_RV_MODEL));
    if (model.isNull()) return null;
    const head = readPtr(model.add(OFF_MODEL_HEAD));
    if (head.isNull()) return null;
    return getTransformPosition(head);
}

function distSq(a, b) {
    const dx = a.x - b.x, dy = a.y - b.y, dz = a.z - b.z;
    return dx * dx + dy * dy + dz * dz;
}

function resolveFkaMethodPtr() {
    const rangeCls = findClass('', 'ItemEquipWeaponRange');
    if (rangeCls.isNull()) {
        console.log('[silent-aim] ItemEquipWeaponRange class not found');
        return null;
    }
    const mi = api.class_get_method_from_name(rangeCls, 'fka', 2);
    if (mi.isNull()) {
        console.log('[silent-aim] fka method not found');
        return null;
    }
    const methodPtr = readPtr(mi);
    console.log('[silent-aim] fka mi=' + mi + ' methodPtr=' + methodPtr);
    return methodPtr;
}

// Set this to a world-space enemy head position to force silent aim at it.
// Coordinates can be read from the [shot] lines of frida/logger.js or from
// the [silent-aim] fka lines below.
const TARGET_POS = null; // { x: 123.4, y: 1.6, z: 56.7 }

function install() {
    if (Process.arch !== 'arm64') {
        throw new Error('silent-aim expects arm64');
    }
    bindApi();

    const fkaPtr = resolveFkaMethodPtr();
    if (fkaPtr === null || fkaPtr.isNull()) {
        return;
    }

    console.log('[silent-aim] attaching Interceptor to fka at ' + fkaPtr);

    Interceptor.attach(fkaPtr, {
        onEnter: function (args) {
            // fka(Vector3 from, Vector3 to, void* mi) — arm64: from in s0-s2, to in s3-s5.
            const from = readVec3Regs(this.context, 0);
            const to = readVec3Regs(this.context, 3);
            const dir = { x: to.x - from.x, y: to.y - from.y, z: to.z - from.z };
            const len = Math.sqrt(dir.x * dir.x + dir.y * dir.y + dir.z * dir.z);
            if (!Number.isFinite(len) || len < 0.05) return;

            console.log('[silent-aim] fka from=(' +
                from.x.toFixed(1) + ',' + from.y.toFixed(1) + ',' + from.z.toFixed(1) + ') ' +
                'to=(' + to.x.toFixed(1) + ',' + to.y.toFixed(1) + ',' + to.z.toFixed(1) + ')');

            let target = TARGET_POS;
            if (target === null) return;

            const targetLen = Math.sqrt(
                (target.x - from.x) * (target.x - from.x) +
                (target.y - from.y) * (target.y - from.y) +
                (target.z - from.z) * (target.z - from.z)
            );
            if (targetLen < 0.05 || targetLen > MAX_SHOT_RANGE) return;

            // Keep original travel distance so range/falloff checks still see a plausible shot.
            const scale = len / targetLen;
            const newTo = {
                x: from.x + (target.x - from.x) * scale,
                y: from.y + (target.y - from.y) * scale,
                z: from.z + (target.z - from.z) * scale
            };
            writeVec3Regs(this.context, 3, newTo);

            console.log('[silent-aim] fka redirected to=(' +
                newTo.x.toFixed(2) + ',' + newTo.y.toFixed(2) + ',' + newTo.z.toFixed(2) + ')');
        },
        onLeave: function (retval) {
            // no-op
        }
    });
}

setImmediate(install);

