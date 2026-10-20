"""Pure bounded fake-memory closure checks; no process or game is opened."""
import copy
import json
import struct
from types import SimpleNamespace
import runtime_capture_41 as tool


def check():
    passed = []
    for case in ("valid", "null", "overflow", "last-valid-byte", "unmapped", "short",
                 "staff-alias", "attribute-alias", "caller", "missing-slot", "constant-short",
                 "relocated"):
        esp, slot, staff, attrs = 0x100000, 0x200000, 0x300000, 0x400000
        if case == "null": attrs = 0
        if case == "overflow": attrs = 0xFFFFFFFF
        if case == "last-valid-byte": attrs = 0xFFFFFFD2
        image = 0x500000 if case == "relocated" else 0x400000
        delta = image - 0x400000
        stack, record, candidate = bytearray(0x300), bytearray(0x6E), bytearray(0x1BE)
        struct.pack_into("<II", stack, 0x260, 0x6CF8F7 + delta + (case == "caller"), staff)
        struct.pack_into("<I", record, 0x61, attrs + (case == "attribute-alias"))
        struct.pack_into("<II", candidate, 0x69, staff + (case == "staff-alias"), attrs)
        blocks = {esp - 0x260: bytes(stack), staff: bytes(record), slot: bytes(candidate)}
        class Memory:
            def __init__(self): self.calls = []
            def read(self, process, address, size):
                tool.base.require(0 <= address < 2**32 and address + size <= 2**32, "unsafe read")
                self.calls.append((address, size))
                data = blocks.get(address, bytes(size))
                if address == attrs + 0x2D and case in ("unmapped", "short"):
                    data = b""
                if address == slot and case == "missing-slot": data = b""
                if address == image + 0x567F28 and case == "constant-short": data = bytes(2)
                return {"address": address, "requested": size, "received": len(data),
                        "complete": len(data) == size, "winerror": 0 if len(data) == size or case == "short" else 299,
                        "hex": data.hex(), "sha256": tool.base.hashlib.sha256(data).hexdigest()}
        memory = Memory()
        ctx = SimpleNamespace(Esp=esp, Esi=slot, Ecx=0)
        closure = tool.lookup_closure(memory, None, ctx, image, effect_inputs=True)
        inputs = closure["effect_inputs"]
        expected = {"null": "null-attribute-pointer", "overflow": "outside-x86-address-space",
                    "staff-alias": "alias-mismatch", "attribute-alias": "alias-mismatch",
                    "caller": "caller-mismatch", "missing-slot": "missing-alias-input"}
        tool.base.require(inputs["status"] == expected.get(case, "admitted-address"), case + " status")
        admitted = case not in expected
        tool.base.require(((attrs + 0x2D, 1) in memory.calls) == admitted, case + " dereference gate")
        tool.base.require(inputs["read_complete"] == (admitted and case not in ("unmapped", "short")),
                          case + " completeness")
        effect = [r for r in closure["memory"] if r["label"].startswith("effect_") and
                  r["label"] != "effect_esi_candidate_slot"]
        tool.base.require(sum(r["requested"] for r in effect) == 4 + int(admitted), "byte budget")
        tool.base.require((image + 0x567F28, 4) in memory.calls, "constant relocation")
        if case == "constant-short":
            tool.base.require(not closure["all_requested_reads_complete"], "short constant hidden")
        returned = tool.effect_input_return(closure, closure["memory"], True)
        tool.base.require(inputs["constant_complete"] == (case != "constant-short") and
                          returned["constant_complete"] == inputs["constant_complete"], "constant completeness")
        tool.base.require(returned["current_attribute_complete"] == inputs["read_complete"],
                          case + " return completeness")
        if case == "valid":
            for change in ("both-pointers", "slot-pointer", "staff-pointer", "slot-register", "return-short"):
                after = copy.deepcopy(closure["memory"])
                for r in after:
                    data = bytearray.fromhex(r["hex"])
                    if r["label"] == "effect_esi_candidate_slot" and change in ("both-pointers", "slot-pointer"):
                        struct.pack_into("<I", data, 0x6D, attrs + 100)
                    if r["label"] == "staff_record" and change in ("both-pointers", "staff-pointer"):
                        struct.pack_into("<I", data, 0x61, attrs + 100)
                    if r["label"] == "effect_attribute_byte" and change == "return-short":
                        data = bytearray()
                        r.update(complete=False, received=0)
                    r["hex"] = data.hex()
                    r["sha256"] = tool.base.hashlib.sha256(data).hexdigest()
                answer = tool.effect_input_return(closure, after, change != "slot-register")
                expected_return = {"both-pointers": "pointer-changed-or-entry-unavailable",
                    "slot-pointer": "alias-mismatch", "staff-pointer": "alias-mismatch",
                    "slot-register": "slot-register-changed", "return-short": "incomplete-read"}[change]
                tool.base.require(not answer["current_attribute_complete"] and answer["status"] == expected_return,
                                  change + " false current attribute")
                passed.append("return-" + change)
            legacy = Memory()
            single = tool.lookup_closure(legacy, None, ctx, image)
            tool.base.require(single["effect_inputs"] is None and
                (image + 0x567F28, 4) not in legacy.calls and (attrs + 0x2D, 1) not in legacy.calls,
                "unpaired capture expanded")
            passed.append("unpaired-unchanged")
        passed.append(case)
    return passed


if __name__ == "__main__":
    print(json.dumps({"schema": "reversal.runtime-effect-input-41.check.v1", "optimized": not __debug__,
                      "cases": check(), "scope": "synthetic fake memory only"}))
