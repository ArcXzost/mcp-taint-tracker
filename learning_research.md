# Post-MVP Research: Auto-Tune Learning Pipeline

## The Problem Statement
Our system relies on flow attribution (Lexical and Semantic) to detect when tainted data moves through an agent's context. These engines rely on confidence thresholds (e.g., Semantic > 0.55). If the threshold is too high, we suffer False Negatives (FN - breaches). If it's too low, we suffer False Positives (FP - alert fatigue).

The goal of the "Auto-Tune" pipeline is to automatically adjust these thresholds based on human SOC analyst feedback (Triage: TP / FP).

## Research: ML Approaches for Threshold Optimization

### 1. Stochastic Gradient Descent (SGD) / Logistic Regression
*   **Concept:** Treat the flow confidence score as a feature and train a logistic regression model incrementally as feedback arrives. The "threshold" becomes the decision boundary.
*   **Pros:** Extremely fast, supports online streaming updates (no need to store all historical data).
*   **Cons:** Black-box decision boundary. Hard to enforce strict asymmetry (cost of FN vs FP) dynamically without complex class-weighting math that can destabilize.

### 2. Bayesian Optimization (e.g., Optuna)
*   **Concept:** Model the threshold space probabilistically. Evaluate combinations of thresholds to maximize a specific objective function.
*   **Pros:** Highly mathematically rigorous. Can easily incorporate complex objective functions.
*   **Cons:** Computationally expensive. Typically requires retraining on the entire dataset, making it unscalable for large SIEM deployments unless aggressive sampling is used.

### 3. Multi-Armed Bandits (MAB)
*   **Concept:** Continuously test different thresholds in real-time to find the optimal balance between exploration (trying a new threshold) and exploitation (using the best known).
*   **Pros:** Adapts instantly to concept drift.
*   **Cons:** Completely unacceptable for cybersecurity. "Exploring" a 0.95 threshold to see what happens will intentionally cause False Negatives (breaches).

### 4. Time-Weighted Empirical F-Beta Optimization (The Industry Standard)
*   **Concept:** Maintain a sliding window (or time-decayed log) of the last $N$ triage events. Execute a fast, localized grid-search to find the exact threshold that maximizes the $F_\beta$ score (where $\beta$ dictates the weight of Recall over Precision).
*   **Pros:** 100% Explainable. Mathematically guarantees the best empirical result for recent data.
*   **Cons:** Requires storing raw triage history (which we already do via `truth_matrix.csv`).

---

## Brutal Critique & Recommendation for our Use Case

If we are building "Datadog for Agent Execution Graphs," we must optimize for **Explainability** and **Breach Prevention**. 

### The Flaws in our Current (Naive) Pipeline:
1.  **Global Thresholds:** We currently tune a *single* semantic threshold for the entire system. This is a fatal flaw. An `http_request` sink might need a strict 0.80 threshold, while a `memory_write` needs a loose 0.40 threshold because LLMs paraphrase memory.
2.  **F1 Optimization:** We optimize for F1, treating FP and FN equally. In a SOC, a False Negative costs millions of dollars. We must optimize for **F3** (Recall is 3x more important than Precision).
3.  **No Concept Drift:** A click from 2 years ago counts the same as a click from today.

### The Recommendation (Implementation Plan):
We should implement **Approach 4: Time-Weighted Empirical F-Beta Optimization**.

We will rewrite `learning_pipeline.py` to:
1.  **Group by Rule/Sink:** Optimize a *separate* semantic and lexical threshold for *every single YAML rule*.
2.  **Optimize for F3 Score:** `F3 = (10 * Precision * Recall) / ((9 * Precision) + Recall)`. This ensures thresholds drop aggressively to prevent False Negatives, only rising if False Positives become overwhelming.
3.  **Apply Exponential Time-Decay:** Multiply the weight of each CSV row by $e^{-\lambda t}$, so recent analyst feedback dictates the threshold, gracefully "forgetting" outdated attacker techniques.
