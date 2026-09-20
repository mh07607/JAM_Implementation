"""
Binary header parser (bytes -> models.Header), driven by the codec vectors.

Layout verified byte-exact against jamtestvectors/codec/{tiny,full}/header_0
and header_1 and their JSON sidecars (GP C.22–C.25, 0.7.1 vector layout:
no length prefix on epoch-marker validators, seal last).

The Reader (util.py) is used as-is. It is parameterized through util.py's
module globals (NUM_VALIDATORS_IN_EPOCH_MARK, LENGTH_OF_EPOCH_IN_TIMESLOTS),
so parse_header takes a spec name and swaps those globals for the duration
of the parse via the spec_globals() context manager below.
"""

import json
import os
from contextlib import contextmanager

import jam_impl.util as util
from jam_impl.models import Header, EpochMarker, TicketBody
from jam_impl.models.Header import _hb

# Spec constants — jamtestvectors/lib/{tiny,full}-const.asn,
# jam-types-py jam_types/spec.py, and util.py's own globals.
V = {"tiny": 6, "full": 1023}                # validators-count
EPOCH_LENGTH = {"tiny": 12, "full": 600}     # epoch-length

# jamtestvectors/codec/<spec>/<name>.{bin,json} — repo root is this file's
# parent's parent's parent (jam_impl/codec/parse_header.py -> repo root).
VECTOR_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "jamtestvectors", "codec",
)


def vector_path(spec: str, name: str, ext: str = "bin") -> str:
    return os.path.join(VECTOR_DIR, spec, f"{name}.{ext}")


def load_vector(spec: str, name: str) -> tuple[bytes, dict]:
    """Return (binary vector, JSON sidecar dict) for a codec vector."""
    with open(vector_path(spec, name, "bin"), "rb") as f:
        b = f.read()
    with open(vector_path(spec, name, "json")) as f:
        j = json.load(f)
    return b, j


@contextmanager
def spec_globals(spec: str):
    """Point util.py's Reader globals at the chosen spec, then restore.

    'full' is util.py's current default; 'tiny' switches the marker readers
    to 6 validators / 12 tickets per epoch. No Reader code is touched.
    """
    saved = (util.NUM_VALIDATORS_IN_EPOCH_MARK, util.LENGTH_OF_EPOCH_IN_TIMESLOTS)
    util.NUM_VALIDATORS_IN_EPOCH_MARK = V[spec]
    util.LENGTH_OF_EPOCH_IN_TIMESLOTS = EPOCH_LENGTH[spec]
    try:
        yield
    finally:
        util.NUM_VALIDATORS_IN_EPOCH_MARK, util.LENGTH_OF_EPOCH_IN_TIMESLOTS = saved

def encode_epoch_marker(epoch_mark: EpochMarker | None) -> bytes:
    if epoch_mark == None:
        return b"\x00"
    out = b"\x01" + epoch_mark.entropy + epoch_mark.tickets_entropy
    out += b''.join(validator.bandersnatch + validator.ed25519 for validator in epoch_mark.validators)
    return out

def encode_tickets_marker(winning_tickets: list[TicketBody] | None) -> bytes:
    if winning_tickets == None:
        return b"\x00"
    return b"\x01" + b''.join(ticket.id + util.u8(ticket.attempt) for ticket in winning_tickets)

def encode_header(h: Header) -> bytes:
    out = h.parent + h.parent_state_root + h.extrinsic_hash
    out += util.u32(h.slot)
    out += encode_epoch_marker(h.epoch_mark)
    out += encode_tickets_marker(h.tickets_mark)
    out += util.u16(h.author_index)
    out += h.entropy_source
    out += util.encode_compact(len(h.offenders_mark)) + b''.join(h.offenders_mark)
    out += h.seal
    return out

def parse_header(b: bytes, spec: str = "full") -> Header:
    """Parse a serialized header (GP C.22–C.25; 0.7.1 vector layout).

    Wire order: P(32) R(32) X(32) T(4) [E] [W] I(2) V(96) [O] S(96).
    E = option disc + eta0(32) + eta1(32) + V×(bandersnatch 32 + ed25519 32),
    no length prefix on the validator sequence in these vectors (GP 0.8.0
    C.25 adds a compact prefix — not byte-compatible with 0.7.1 fixtures).
    W = option disc + epoch-length×(id 32 + attempt 1).
    O = compact length prefix + n×32 Ed25519 keys.
    Reader.finish() asserts the input is fully consumed.
    """
    with spec_globals(spec):
        r = util.Reader(b)
        parent = r.hash32()
        parent_state_root = r.hash32()
        extrinsic_hash = r.hash32()
        slot = r.u32()
        epoch_raw = r.epoch_marker()
        tickets_raw = r.winning_tickets_marker()
        author_index = r.u16()
        entropy_source = r.take(96)
        offenders_raw = r.offenders_marker()
        seal = r.take(96)
        r.finish()

    return Header(
        parent=parent,
        parent_state_root=parent_state_root,
        extrinsic_hash=extrinsic_hash,
        slot=slot,
        epoch_mark=Header.epoch_mark_from_dict(epoch_raw) if epoch_raw is not None else None,
        tickets_mark=Header.tickets_mark_from_list(tickets_raw) if tickets_raw is not None else None,
        author_index=author_index,
        entropy_source=entropy_source,
        offenders_mark=[_hb(k) for k in (offenders_raw or [])],
        seal=seal,
    )