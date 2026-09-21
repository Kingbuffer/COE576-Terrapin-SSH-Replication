#!/usr/bin/env python3
"""Regenerate raw CSVs, measured summaries and original plots with one command."""
import argparse,csv,json,platform,random
from pathlib import Path
import cryptography,matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from src.terrapin import experiment

ROOT=Path(__file__).resolve().parent

def write_csv(path,rows):
    with path.open('w',newline='') as f:
        w=csv.DictWriter(f,fieldnames=list(rows[0])); w.writeheader();w.writerows(rows)

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--trials',type=int,default=1000)
    ap.add_argument('--grid-trials',type=int,default=100);ap.add_argument('--seed',type=int,default=57611)
    a=ap.parse_args()
    if a.trials<1 or a.grid_trials<1: ap.error('trial counts must be positive')
    for d in ['results','figures']: (ROOT/d).mkdir(exist_ok=True)
    rng=random.Random(a.seed)
    cases=[('Clean legacy',dict(injected=0,dropped=0)),
           ('Drop only',dict(injected=0,dropped=1)),
           ('Inject only',dict(injected=1,dropped=0)),
           ('Matched truncation',dict(injected=1,dropped=1)),
           ('Reset only',dict(injected=1,dropped=1,reset=True)),
           ('Reject optional only',dict(injected=1,dropped=1,reject_optional=True)),
           ('Strict KEX model',dict(injected=1,dropped=1,reset=True,reject_optional=True)),
           ('Tampered ciphertext',dict(injected=1,dropped=1,tamper=True)),
           ('Clean strict KEX',dict(injected=0,dropped=0,reset=True,reject_optional=True))]
    raw=[]; summary=[]
    for name,kwargs in cases:
        rows=[dict(case=name,trial=t,**experiment(rng,**kwargs)) for t in range(a.trials)]
        raw.extend(rows)
        summary.append(dict(case=name,trials=a.trials,accepted=sum(r['accepted'] for r in rows),
                            prefix_removed=sum(r['prefix_removed'] for r in rows),
                            ext_missing=sum(r['ext_missing'] for r in rows)))
    write_csv(ROOT/'results/trials.csv',raw);write_csv(ROOT/'results/summary.csv',summary)
    grid=[]; gridraw=[]; matrix=[]
    for i in range(9):
        line=[]
        for d in range(9):
            rows=[dict(injected=i,dropped=d,trial=t,**experiment(rng,i,d)) for t in range(a.grid_trials)]
            gridraw.extend(rows); rate=sum(r['accepted'] for r in rows)/a.grid_trials
            grid.append(dict(injected=i,dropped=d,trials=a.grid_trials,accepted_rate=rate))
            line.append(rate)
        matrix.append(line)
    write_csv(ROOT/'results/grid.csv',grid);write_csv(ROOT/'results/grid_trials.csv',gridraw)
    meta=dict(seed=a.seed,trials=a.trials,grid_trials=a.grid_trials,packet_count=12,
              python=platform.python_version(),cryptography=cryptography.__version__,
              matplotlib=matplotlib.__version__,scope='Offline framed SSH ChaCha20-Poly1305 packet experiment; no live SSH endpoints')
    (ROOT/'results/metadata.json').write_text(json.dumps(meta,indent=2)+'\n')
    plt.rcParams.update({'font.family':'DejaVu Sans','font.size':13,'axes.spines.top':False,'axes.spines.right':False})
    fig,ax=plt.subplots(figsize=(10,5.4),layout='constrained')
    rates=[r['accepted']/a.trials*100 for r in summary]
    bars=ax.barh([r['case'] for r in summary],rates,color=['#3D8DFF' if x else '#b8bcc4' for x in rates])
    ax.invert_yaxis();ax.set_xlim(0,115);ax.set_xlabel('Remaining stream accepted intact (%)')
    for bar,r in zip(bars,summary): ax.text(max(1,bar.get_width()+1),bar.get_y()+bar.get_height()/2,f"{r['accepted']}/{a.trials}",va='center',fontsize=11)
    ax.set_xticks([0,25,50,75,100]);fig.savefig(ROOT/'figures/control_results.png',dpi=180);plt.close(fig)
    fig,ax=plt.subplots(figsize=(7,6),layout='constrained')
    ax.imshow(matrix,vmin=0,vmax=1,cmap='Blues',origin='lower')
    ax.set_xticks(range(9));ax.set_yticks(range(9));ax.set_xlabel('Encrypted prefix packets deleted (d)')
    ax.set_ylabel('Handshake IGNORE packets injected (i)')
    for i in range(9):
        for d in range(9): ax.text(d,i,f'{matrix[i][d]:.0%}',ha='center',va='center',color='white' if matrix[i][d] else '#777777',fontsize=10)
    fig.savefig(ROOT/'figures/count_sensitivity.png',dpi=180);plt.close(fig)
    print(json.dumps({'summary':summary,'grid_cells':len(grid),'total_trials':len(raw)+len(gridraw)},indent=2))

if __name__=='__main__': main()
