"""Phase 9: the shared Substitutor and its cache/store are touched by every
transform call. Under parallel calls the keyed output must stay deterministic and
uncorrupted, and separate keys must not cross-contaminate."""
import threading

import pandas as pd

from proxy.ingest import Table
from proxy.transform import Transformer


def _rows(n=50):
    return Table(pd.DataFrame({"email": [f"u{i}@x.com" for i in range(n)]}))


def test_shared_substitutor_is_deterministic_under_threads():
    tr = Transformer(key="K")
    rows = _rows()
    out = []

    def work():
        out.append(tuple(tr.transform_table(rows, {"email": "EMAIL_ADDRESS"})[0].df["email"]))

    threads = [threading.Thread(target=work) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(set(out)) == 1                                 # no corruption across threads
    fresh = tuple(Transformer(key="K").transform_table(rows, {"email": "EMAIL_ADDRESS"})[0].df["email"])
    assert out[0] == fresh                                    # matches a clean single-threaded run


def test_separate_keys_do_not_cross_contaminate():
    rows = Table(pd.DataFrame({"email": ["a@x.com"] * 20}))
    ta, tb = Transformer(key="A"), Transformer(key="B")
    a_res, b_res = [], []

    def wa():
        a_res.append(ta.transform_table(rows, {"email": "EMAIL_ADDRESS"})[0].df["email"][0])

    def wb():
        b_res.append(tb.transform_table(rows, {"email": "EMAIL_ADDRESS"})[0].df["email"][0])

    threads = [threading.Thread(target=wa) for _ in range(4)] + \
              [threading.Thread(target=wb) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(set(a_res)) == 1 and len(set(b_res)) == 1     # each key internally consistent
    assert a_res[0] != b_res[0]                               # and isolated from each other
