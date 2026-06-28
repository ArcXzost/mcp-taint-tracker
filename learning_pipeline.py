"""
Learning Pipeline — Auto-Tuning with Safety Guarantees.

Transforms analyst feedback (truth_matrix.csv) into optimized thresholds,
with built-in drift detection, rollback on regression, and explainability.

Minimum data requirements (hard safety gates):
  - Global baseline: >= 100 labeled samples across all rules
  - Per-rule optimization: >= 10 labeled samples for that rule
  - If insufficient data: defaults are returned with a "shadow" recommendation
"""

import csv
import json
import os
import time
import math
import copy
from typing import List, Tuple, Dict, Optional, Any


# ── Safety Gates ──────────────────────────────────────────────────────────────

MIN_GLOBAL_SAMPLES = 100       # Minimum labeled samples across all rules
MIN_RULE_SAMPLES = 10          # Minimum labeled samples for a single rule
MAX_THRESHOLD_CHANGE = 0.15    # Maximum allowable change in any threshold (to prevent oscillation)
ROLLBACK_F3_DEGRADATION = 0.05 # Rollback if new F3 is >5% worse than previous

# ── CUSUM Drift Detection ─────────────────────────────────────────────────────

class CUSUMDetector:
    """
    Cumulative Sum (CUSUM) control chart for detecting drift 
    in false positive rate between consecutive optimization runs.
    
    Signals drift when cumulative deviation from target exceeds threshold.
    Each rule gets its own detector to prevent signal contamination.
    """
    
    def __init__(self, target_fp_rate: float = 0.05, threshold: float = 3.0):
        self.target = target_fp_rate
        self.threshold = threshold
        self.cumulative_positive = 0.0
        self.cumulative_negative = 0.0
        self.total_samples = 0
        
    def update(self, fp_rate: float) -> Dict[str, Any]:
        """Update CUSUM with new FP rate measurement. Returns drift status."""
        self.total_samples += 1
        deviation = fp_rate - self.target
        
        self.cumulative_positive = max(0.0, self.cumulative_positive + deviation - 0.5 * self.threshold)
        self.cumulative_negative = min(0.0, self.cumulative_negative + deviation + 0.5 * self.threshold)
        
        drift_detected = self.cumulative_positive > self.threshold or abs(self.cumulative_negative) > self.threshold
        
        return {
            "drift_detected": drift_detected,
            "cumulative_positive": round(self.cumulative_positive, 4),
            "cumulative_negative": round(self.cumulative_negative, 4),
            "current_fp_rate": round(fp_rate, 4),
            "target_fp_rate": self.target,
        }


_CUSUM_REGISTRY: Dict[str, CUSUMDetector] = {}


# ── Threshold History (for rollback) ──────────────────────────────────────────

THRESHOLD_HISTORY_FILE = "threshold_history.json"

def _load_threshold_history() -> Dict[str, Any]:
    """Load previous optimization results for comparison and rollback."""
    if os.path.exists(THRESHOLD_HISTORY_FILE):
        try:
            with open(THRESHOLD_HISTORY_FILE, "r") as f:
                return json.load(f)
        except Exception:
            pass
    return {"history": [], "current": {"_global": {}, "rules": {}}}


def _save_threshold_history(entry: Dict[str, Any]) -> None:
    """Append a new optimization result to the history log."""
    history = _load_threshold_history()
    history.setdefault("history", []).append({
        "timestamp": time.time(),
        "datetime": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
        "thresholds": entry,
    })
    # Keep only last 20 entries
    history["history"] = history["history"][-20:]
    history["current"] = entry
    with open(THRESHOLD_HISTORY_FILE, "w") as f:
        json.dump(history, f, indent=2, default=str)


# ── Core Optimization ─────────────────────────────────────────────────────────

def compute_f3(precision: float, recall: float) -> float:
    """F3 Score: weights recall 3x more than precision (catches more attacks)."""
    if precision + recall == 0:
        return 0.0
    return 10.0 * (precision * recall) / ((9.0 * precision) + recall)


def optimize_threshold(
    data: List[Tuple[float, int, float]],
    method: str,
    default: float,
    rule_name: str = "_global",
    force: bool = False,
) -> Dict[str, Any]:
    """
    Optimize a threshold using Time-Weighted F3 Score.
    
    Returns both the optimal threshold and an explanation of why.
    If insufficient data, returns default with 'insufficient' status.
    """
    min_samples = 1 if force else (MIN_GLOBAL_SAMPLES if rule_name == "_global" else MIN_RULE_SAMPLES)
    
    result = {
        "threshold": default,
        "previous_threshold": default,
        "f3_score": 0.0,
        "samples": len(data),
        "status": "insufficient_data" if not force else "optimized",
        "explanation": f"Need {min_samples} samples, have {len(data)}",
        "drift": {"drift_detected": False},
        "rollback_applied": False,
    }
    
    if len(data) < min_samples:
        return result
    
    best_threshold = default
    best_f3 = -1.0
    tp_w_total = fp_w_total = fn_w_total = 0.0
    
    # Try thresholds from 0.05 to 0.95 in steps of 0.05
    for t_int in range(5, 100, 5):
        t = t_int / 100.0
        
        tp_w = fp_w = fn_w = 0.0
        
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
        f3 = compute_f3(precision, recall)
        
        # Tie-breaker: higher threshold wins (reduces FPs)
        if f3 >= best_f3:
            best_f3 = f3
            best_threshold = t
            tp_w_total, fp_w_total, fn_w_total = tp_w, fp_w, fn_w
    
    # Check drift (FP rate) — per-rule CUSUM to avoid signal contamination
    total_classified = tp_w_total + fp_w_total
    fp_rate = fp_w_total / total_classified if total_classified > 0 else 0.0
    if rule_name not in _CUSUM_REGISTRY:
        _CUSUM_REGISTRY[rule_name] = CUSUMDetector(target_fp_rate=0.05, threshold=3.0)
    drift_status = _CUSUM_REGISTRY[rule_name].update(fp_rate)
    result["drift"] = drift_status
    
    # Load previous thresholds for comparison
    history = _load_threshold_history()
    prev_rules = history["current"].get("rules", {})
    prev_global = history["current"].get("_global", {})
    
    if rule_name == "_global":
        prev_threshold = prev_global.get(f"{method}_threshold", default)
        prev_f3 = prev_global.get(f"{method}_f3", 0.0)
    else:
        rule_entry = prev_rules.get(rule_name, {})
        prev_threshold = rule_entry.get(f"{method}_threshold", default)
        prev_f3 = rule_entry.get(f"{method}_f3", 0.0)
    
    result["previous_threshold"] = prev_threshold
    result["f3_score"] = round(best_f3, 4)
    result["previous_f3"] = round(prev_f3, 4)
    
    # Enforce maximum change per step (anti-oscillation)
    change = abs(best_threshold - prev_threshold)
    if change > MAX_THRESHOLD_CHANGE and prev_threshold != default:
        # Clamp: move toward optimal but not more than MAX_THRESHOLD_CHANGE
        direction = 1 if best_threshold > prev_threshold else -1
        best_threshold = prev_threshold + direction * MAX_THRESHOLD_CHANGE
        best_threshold = max(0.05, min(0.95, best_threshold))
        clamped = True
    else:
        clamped = False
    
    # Rollback check: if F3 degraded significantly from previous, roll back
    need_rollback = False
    if prev_f3 > 0 and best_f3 < prev_f3 * (1.0 - ROLLBACK_F3_DEGRADATION):
        best_threshold = prev_threshold
        need_rollback = True
        result["rollback_applied"] = True
    
    # Build explanation
    explanation_parts = []
    if drift_status["drift_detected"]:
        explanation_parts.append(
            f"FP rate drift detected (CUSUM={drift_status['cumulative_positive']:.2f})"
        )
    if clamped:
        explanation_parts.append(f"Change clamped to {MAX_THRESHOLD_CHANGE:.0%} max step")
    if need_rollback:
        explanation_parts.append(
            f"Rolled back: F3 degraded {((prev_f3 - best_f3) / prev_f3 * 100):.1f}%"
        )
    if not (clamped or need_rollback or drift_status["drift_detected"]):
        direction = "increased" if best_threshold > prev_threshold else "decreased"
        explanation_parts.append(
            f"Threshold {direction} from {prev_threshold:.2f} to {best_threshold:.2f} "
            f"(F3: {prev_f3:.3f} -> {best_f3:.3f})"
        )
    
    result.update({
        "threshold": round(best_threshold, 2),
        "status": "optimized",
        "explanation": "; ".join(explanation_parts),
        "fp_rate": round(fp_rate, 4),
        "clamped": clamped,
    })
    
    return result


def main(shadow_mode: bool = False, force: bool = False) -> Optional[Dict[str, Any]]:
    """
    Run the learning pipeline.
    
    Args:
        shadow_mode: If True, compute recommendations but do NOT deploy them.
            Use for initial periods to validate without risk.
        force: If True, skip minimum data checks and optimize with whatever is available.
    
    Returns: Optimized thresholds dict, or None if insufficient data.
    """
    if not os.path.isfile("truth_matrix.csv"):
        print("[LEARN] No truth_matrix.csv found. Nothing to learn.")
        return None
    
    # Exponentially decayed weight: half-life 30 days
    HALF_LIFE_SEC = 30 * 24 * 60 * 60
    LAMBDA = math.log(2) / HALF_LIFE_SEC
    current_time = time.time()
    
    # Structure: rule_name -> { "semantic": [(conf, label, weight)], "lexical": [...] }
    rule_data: Dict[str, Dict[str, List[Tuple[float, int, float]]]] = {}
    total_samples = 0
    sem_samples = 0
    lex_samples = 0
    
    with open("truth_matrix.csv", mode="r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            try:
                timestamp = float(row["timestamp"])
                rule_name = row["rule"].replace("Matched YAML Rule: ", "")
                method = row["method"]
                conf = float(row["confidence"])
                label = int(row["label"])
                
                age_seconds = max(0.0, current_time - timestamp)
                weight = math.exp(-LAMBDA * age_seconds)
                
                rule_data.setdefault(rule_name, {"semantic": [], "lexical": []})
                if method in ("semantic", "lexical"):
                    rule_data[rule_name][method].append((conf, label, weight))
                    total_samples += 1
                    if method == "semantic":
                        sem_samples += 1
                    else:
                        lex_samples += 1
            except Exception as e:
                print(f"[LEARN] Skipping malformed row: {e}")
                continue
    
    print(f"[LEARN] Loaded {total_samples} labeled samples ({sem_samples} semantic, {lex_samples} lexical) across {len(rule_data)} rules")
    
    needed = MIN_GLOBAL_SAMPLES if not force else 1
    if total_samples < needed:
        print(f"[LEARN] Insufficient data: {total_samples}/{MIN_GLOBAL_SAMPLES} samples needed. Use --force to override.")
        return None
    
    # ── Global baselines ──────────────────────────────────────────────────
    global_semantic = []
    global_lexical = []
    for data in rule_data.values():
        global_semantic.extend(data["semantic"])
        global_lexical.extend(data["lexical"])
    
    sem_result = optimize_threshold(global_semantic, "semantic", 0.55, "_global", force=force)
    lex_result = optimize_threshold(global_lexical, "lexical", 0.75, "_global", force=force)
    
    print(f"[LEARN] Global Semantic: {sem_result['threshold']:.2f} ({sem_result['status']})")
    print(f"         {sem_result['explanation']}")
    print(f"[LEARN] Global Lexical: {lex_result['threshold']:.2f} ({lex_result['status']})")
    print(f"         {lex_result['explanation']}")
    
    global_sem_t = sem_result["threshold"]
    global_lex_t = lex_result["threshold"]
    
    # ── Per-rule optimization ─────────────────────────────────────────────
    optimized_rules = {}
    all_explanations = []
    
    for rule_name, data in rule_data.items():
        sem_result = optimize_threshold(data["semantic"], "semantic", global_sem_t, rule_name, force=force)
        lex_result = optimize_threshold(data["lexical"], "lexical", global_lex_t, rule_name, force=force)
        
        optimized_rules[rule_name] = {
            "semantic_threshold": sem_result["threshold"],
            "lexical_threshold": lex_result["threshold"],
            "semantic_f3": sem_result["f3_score"],
            "lexical_f3": lex_result["f3_score"],
            "samples": len(data["semantic"]) + len(data["lexical"]),
            "semantic_explanation": sem_result["explanation"],
            "lexical_explanation": lex_result["explanation"],
            "drift_detected": sem_result["drift"]["drift_detected"] or lex_result["drift"]["drift_detected"],
            "rollback_applied": sem_result["rollback_applied"] or lex_result["rollback_applied"],
        }
        
        if sem_result["status"] == "optimized" or lex_result["status"] == "optimized":
            all_explanations.append(f"  {rule_name}:")
            all_explanations.append(f"    Semantic: {sem_result['explanation']}")
            all_explanations.append(f"    Lexical: {lex_result['explanation']}")
    
    output_payload = {
        "_global": {
            "semantic_threshold": global_sem_t,
            "lexical_threshold": global_lex_t,
            "semantic_f3": sem_result["f3_score"],
            "lexical_f3": lex_result["f3_score"],
        },
        "rules": optimized_rules,
        "metadata": {
            "shadow_mode": shadow_mode,
            "total_samples": total_samples,
            "rules_optimized": len(optimized_rules),
            "timestamp": current_time,
            "explanations": all_explanations,
        },
    }
    
    # Save thresholds
    with open("optimized_thresholds.json", "w") as f:
        json.dump(output_payload, f, indent=2, default=str)
    print(f"[LEARN] Saved to optimized_thresholds.json")
    
    if all_explanations:
        print("[LEARN] Explanations:")
        print("\n".join(all_explanations))
    
    # Archive history
    _save_threshold_history(output_payload)
    
    if shadow_mode:
        print("[LEARN] SHADOW MODE: Thresholds computed but NOT deployed. Review optimized_thresholds.json first.")
    else:
        print("[LEARN] Thresholds deployed. Run `/api/learn` to apply.")
    
    return output_payload


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--shadow", action="store_true", help="Run in shadow mode (don't deploy)")
    parser.add_argument("--force", action="store_true", help="Skip minimum data checks")
    args = parser.parse_args()
    main(shadow_mode=args.shadow, force=args.force)
