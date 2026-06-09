def calculate_score(findings):
    """
    Takes a direct list of finding dictionaries and calculates the penalty score.
    """
    score = 100
    
    # Defensive check to ensure we are iterating over a valid list
    if not isinstance(findings, list):
        return score
        
    for finding in findings:
        # Safely extract the severity using .get() on the dictionary item
        severity = finding.get('severity')
        
        if severity == 'High':
            score -= 20
        elif severity == 'Medium':
            score -= 10
        elif severity == 'Low':
            score -= 5
            
    # Prevent the score from dropping below zero
    return max(0, score)