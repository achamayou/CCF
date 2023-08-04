import sys
import polars as pl
import matplotlib.pyplot as plt

fontsize = 9
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
    "xtick.bottom": False,
    "ytick.right": True,
    "xtick.minor.visible": True,
    "ytick.minor.visible": True,
    "lines.linewidth": 2,
    "legend.frameon": False,
    "axes.grid": False,
    "savefig.bbox": "tight",
}

def recv_per(agg, bucket_period="100ms"):
    return agg.with_columns(
                        pl.col("receiveTime").dt.truncate(bucket_period).alias(bucket_period),
                    ).groupby(bucket_period).count().rename({"count": "rcvd"}).sort(bucket_period)
    
def main(path):
    plt.rcParams.update(params)
    agg = pl.read_parquet(path)
    pl.Config.set_tbl_cols(agg.shape[1])
    print(agg)
    for verb, marker in [(b"GET",  "bo"), (b"PUT", "ro")]:
        verb_agg = agg.filter(pl.col("request").bin.contains(verb))
        period = "100ms"
        recv_per_100ms = recv_per(verb_agg, period)
        print(recv_per_100ms)
        plt.plot(recv_per_100ms[period], recv_per_100ms["rcvd"], marker, markersize=2)
    plt.savefig("agg.pdf")
    plt.close()

if __name__ == '__main__':
    main(sys.argv[1])