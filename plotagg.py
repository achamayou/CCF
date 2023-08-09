import sys
import polars as pl
import matplotlib.pyplot as plt
import json
from datetime import datetime

fontsize = 6
params = {
    "axes.labelsize": fontsize,
    "font.size": fontsize,
    "legend.fontsize": fontsize,
    "xtick.labelsize": fontsize,
    "ytick.labelsize": fontsize,
    "figure.figsize": (8, 2.5),
    "xtick.direction": "in",
    "ytick.direction": "in",
    "xtick.top": False,
    "xtick.bottom": True,
    "ytick.right": True,
    "xtick.minor.visible": True,
    "ytick.minor.visible": True,
    "lines.linewidth": 2,
    "legend.frameon": False,
    "axes.grid": True,
    "savefig.bbox": "tight",
}

def recv_per(agg, bucket_period="100ms"):
    return agg.with_columns(
                        pl.col("receiveTime").dt.truncate(bucket_period).alias(bucket_period),
                    ).groupby(bucket_period).count().rename({"count": "rcvd"}).sort(bucket_period)
    
def main(path, stats_path):
    plt.rcParams.update(params)
    agg = pl.read_parquet(path)
    stats = json.load(open(stats_path))
    pl.Config.set_tbl_cols(agg.shape[1])
    ax = plt.subplot(111)

    series = [(b"GET",  "bo"), (b"PUT", "ro"), (b"PUT 5xx", "yo")]
    for verb, marker in series:
        if verb.endswith(b" 5xx"):
            verb_agg = agg.filter(pl.col("responseStatus") >= 500).filter(pl.col("request").bin.contains(verb.decode().split(" ")[0].encode()))
        else:
            verb_agg = agg.filter(pl.col("responseStatus") < 500).filter(pl.col("request").bin.contains(verb))
        period = "100ms"
        recv_per_100ms = recv_per(verb_agg, period)
        ax.plot(recv_per_100ms[period], recv_per_100ms["rcvd"], marker, markersize=2)
    
    events = [
        ("initial_primary_shutdown_time", "kX"),
        ("new_node_join_start_time", "g^"),
        ("node_replacement_governance_start", "g3"),
        ("node_replacement_governance_committed", "g4"),
        ("old_node_removal_committed", "gD")
    ]
    offset = 0
    for event, marker in events:
        x = datetime.fromisoformat(stats[event])
        ax.plot([x], [0 + (offset % 2) * 1000], marker, markersize=4)
        offset += 1

    # Shrink current axis's height by 10% on the bottom
    box = ax.get_position()
    ax.set_position([box.x0, box.y0 + box.height * 0.1,
                 box.width, box.height * 0.9])


    ax.legend([label.decode() for label, _ in series] + [event for event, _ in events], loc="upper center", ncol=4, bbox_to_anchor=(0.5, -0.05))
    plt.savefig("agg.pdf")
    plt.close()

if __name__ == '__main__':
    main(sys.argv[1], sys.argv[2])