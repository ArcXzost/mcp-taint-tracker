import csv
import json
import os
import numpy as np

def compute_f1(y_true, y_pred):
    tp = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 1)
    fp = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 1)
    fn = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 0)
    
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
    return f1

def optimize_threshold(data, method_name, default_threshold):
    # data is list of (confidence_score, label)
    scores = [d[0] for d in data]
    labels = [d[1] for d in data]
    
    if not scores:
        return default_threshold
        
    best_f1 = -1
    best_thresh = default_threshold
    
    # Grid search between 0.0 and 1.0
    for thresh in np.arange(0.1, 1.0, 0.01):
        y_pred = [1 if s >= thresh else 0 for s in scores]
        f1 = compute_f1(labels, y_pred)
        if f1 > best_f1:
            best_f1 = f1
            best_thresh = thresh
            
    print(f"[{method_name}] Optimized threshold: {best_thresh:.2f} (F1: {best_f1:.2f})")
    return round(best_thresh, 2)

def main():
    print("Running Learning Pipeline...")
    csv_path = "truth_matrix.csv"
    if not os.path.exists(csv_path):
        print("No truth_matrix.csv found. Run the simulation and triage alerts first.")
        return
        
    semantic_data = []
    lexical_data = []
    
    with open(csv_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            method = row["method"]
            conf = float(row["confidence"])
            label = int(row["label"])
            
            if method == "semantic":
                semantic_data.append((conf, label))
            elif method == "lexical":
                lexical_data.append((conf, label))

    print(f"Loaded {len(semantic_data)} semantic samples, {len(lexical_data)} lexical samples.")
    
    new_semantic = optimize_threshold(semantic_data, "semantic", 0.55)
    new_lexical = optimize_threshold(lexical_data, "lexical", 0.75)
    
    thresholds = {
        "semantic_threshold": new_semantic,
        "lexical_threshold": new_lexical
    }
    
    with open("optimized_thresholds.json", "w") as f:
        json.dump(thresholds, f, indent=4)
        
    print("Saved optimized thresholds to optimized_thresholds.json.")

if __name__ == "__main__":
    main()
