import csv
import json
import os
import time
import math
from typing import List, Tuple, Dict

def optimize_threshold(data: List[Tuple[float, int, float]], method: str, default: float) -> float:
    """
    Finds the optimal threshold for a set of data using a Time-Weighted F3 Score.
    data is a list of tuples: (confidence, label, weight)
    label: 1 for TP, 0 for FP
    weight: exponentially decayed weight based on time
    """
    if not data:
        return default
        
    best_threshold = default
    best_f3 = -1.0
    
    # Try thresholds from 0.05 to 0.95 in steps of 0.05
    for t_int in range(5, 100, 5):
        t = t_int / 100.0
        
        tp_w = 0.0
        fp_w = 0.0
        fn_w = 0.0
        
        for conf, label, weight in data:
            if conf >= t:
                if label == 1:
                    tp_w += weight
                else:
                    fp_w += weight
            else:
                if label == 1:
                    fn_w += weight
                    
        precision = tp_w / (tp_w + fp_w) if (tp_w + fp_w) > 0 else 0.0
        recall = tp_w / (tp_w + fn_w) if (tp_w + fn_w) > 0 else 0.0
        
        if precision + recall > 0:
            # F3 Score: beta = 3
            # F_beta = (1 + beta^2) * (P * R) / ((beta^2 * P) + R)
            f3 = 10.0 * (precision * recall) / ((9.0 * precision) + recall)
        else:
            f3 = 0.0
            
        # Tie-breaker: choose the higher threshold to reduce FPs if F3 is identical
        if f3 >= best_f3:
            best_f3 = f3
            best_threshold = t
            
    return best_threshold

def main():
    if not os.path.isfile("truth_matrix.csv"):
        print("No truth_matrix.csv found. Nothing to learn.")
        return

    # Decay rate lambda: 
    # Half-life of 30 days = 30 * 24 * 60 * 60 = 2592000 seconds
    # exp(-lambda * 2592000) = 0.5  => lambda = ln(2) / 2592000
    HALF_LIFE_SEC = 30 * 24 * 60 * 60
    LAMBDA = math.log(2) / HALF_LIFE_SEC
    
    current_time = time.time()
    
    # Structure: rule_name -> { "semantic": [(conf, label, weight)], "lexical": [...] }
    rule_data: Dict[str, Dict[str, List[Tuple[float, int, float]]]] = {}

    with open("truth_matrix.csv", mode="r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            try:
                timestamp = float(row["timestamp"])
                rule_name = row["rule"].replace("Matched YAML Rule: ", "")
                method = row["method"]
                conf = float(row["confidence"])
                label = int(row["label"])
                
                # Calculate time decay weight
                age_seconds = max(0.0, current_time - timestamp)
                weight = math.exp(-LAMBDA * age_seconds)
                
                if rule_name not in rule_data:
                    rule_data[rule_name] = {"semantic": [], "lexical": []}
                    
                if method in ["semantic", "lexical"]:
                    rule_data[rule_name][method].append((conf, label, weight))
            except Exception as e:
                print(f"Skipping malformed row: {e}")
                continue

    # Global fallback data (in case a rule has no history, we still compute a global baseline)
    global_semantic = []
    global_lexical = []
    for data in rule_data.values():
        global_semantic.extend(data["semantic"])
        global_lexical.extend(data["lexical"])
        
    global_sem_t = optimize_threshold(global_semantic, "semantic", 0.55)
    global_lex_t = optimize_threshold(global_lexical, "lexical", 0.75)
    
    print(f"Global Baselines - Semantic: {global_sem_t:.2f}, Lexical: {global_lex_t:.2f}")

    optimized_rules = {}
    
    for rule_name, data in rule_data.items():
        sem_t = optimize_threshold(data["semantic"], "semantic", global_sem_t)
        lex_t = optimize_threshold(data["lexical"], "lexical", global_lex_t)
        
        optimized_rules[rule_name] = {
            "semantic_threshold": sem_t,
            "lexical_threshold": lex_t
        }
        print(f"Rule: {rule_name} -> Sem: {sem_t:.2f}, Lex: {lex_t:.2f}")

    output_payload = {
        "_global": {
            "semantic_threshold": global_sem_t,
            "lexical_threshold": global_lex_t
        },
        "rules": optimized_rules
    }

    with open("optimized_thresholds.json", "w") as f:
        json.dump(output_payload, f, indent=4)
        
    print("Saved optimized rule-specific thresholds to optimized_thresholds.json.")

if __name__ == "__main__":
    main()