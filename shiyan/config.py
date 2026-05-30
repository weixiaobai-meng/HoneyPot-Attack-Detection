class Config:
    # --- 图谱参数 ---
    num_node_types = 5
    node_feat_dim = 16
    hidden_dim = 128
    out_dim = 64
    max_nodes = 40

    # --- GNN 参数 ---
    gnn_layers = 4
    dropout = 0.15

    # --- DQN 参数 ---
    lr = 5e-5
    gamma = 0.0
    epsilon_start = 0.15
    epsilon_end = 0.01
    epsilon_decay = 0.992
    batch_size = 128
    replay_capacity = 10000
    target_update_every = 5

    # --- 训练参数 ---
    num_episodes = 300
    num_train_graphs = 600
    num_val_graphs = 50
    num_test_graphs = 100
    pretrain_epochs = 120
    pretrain_lr = 1e-3
    pretrain_graphs = 100

    # --- 奖励参数 ---
    reward_prune_redundant = 1.0
    reward_keep_core = 5.0
    penalty_prune_core = -10.0
    penalty_keep_redundant = -1.0

    # --- Focal Loss ---
    focal_alpha = 0.75
    focal_gamma = 2.0

    # --- 路径 ---
    model_save_path = "checkpoints/dqn_best.pt"
    log_dir = "logs"

cfg = Config()
