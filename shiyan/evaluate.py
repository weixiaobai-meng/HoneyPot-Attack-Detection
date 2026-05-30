import torch
from dqn_model import DynamicEdgeQNetwork
from data_utils import generate_dataset
from config import cfg
from train import compute_graph_metrics


def evaluate():
    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    print(f"设备: {device}")

    print("\n加载模型...")
    model = DynamicEdgeQNetwork().to(device)
    ckpt = torch.load(cfg.model_save_path, map_location=device)
    if isinstance(ckpt, dict) and 'policy_net' in ckpt:
        model.load_state_dict(ckpt['policy_net'])
    else:
        model.load_state_dict(ckpt)
    model.eval()

    print("生成测试图谱...")
    test_graphs = generate_dataset(cfg.num_test_graphs)

    total = {'ckc': 0, 'cpr': 0, 'wpc': 0, 'wkr': 0}
    metrics_list = []

    for i, g in enumerate(test_graphs):
        g = g.to(device)
        m = compute_graph_metrics(model, g, device)
        for k in total:
            total[k] += m[k]
        metrics_list.append(m)
        if i < 5 or i % 20 == 0:
            print(f"  Graph {i:3d} | Acc: {m['accuracy']:.3f} | "
                  f"F1: {m['f1']:.3f} | CoreRecall: {m['core_recall']:.3f}")

    all_edges = sum(total.values())
    avg = {k: sum(m[k] for m in metrics_list) / len(metrics_list)
           for k in metrics_list[0]}

    print("\n" + "=" * 60)
    print("  汇总结果")
    print("=" * 60)
    print(f"  总边数:         {all_edges}")
    print(f"  正确保留核心:   {total['ckc']}")
    print(f"  正确裁剪冗余:   {total['cpr']}")
    print(f"  错误裁剪核心:   {total['wpc']}")
    print(f"  错误保留冗余:   {total['wkr']}")
    print(f"  准确率:         {avg['accuracy']:.4f}")
    print(f"  精确率:         {avg['precision']:.4f}")
    print(f"  召回率:         {avg['recall']:.4f}")
    print(f"  F1:             {avg['f1']:.4f}")
    print(f"  核心边召回率:   {avg['core_recall']:.4f}")
    print(f"  总奖励:         {avg['total_reward']:.1f}")
    print("=" * 60)


if __name__ == "__main__":
    evaluate()
