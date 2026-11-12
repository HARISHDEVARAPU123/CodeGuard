package com.codeguard.policy;

/**
 * Calculates annual insurance premiums based on policy attributes.
 */
public class PremiumCalculator {

    /**
     * Calculates the annual premium for a given policy.
     *
     * @param policy the policy to evaluate
     * @return the calculated premium
     */
    public double calculatePremium(Policy policy) {
        if (policy == null) {
            throw new IllegalArgumentException("Policy must not be null");
        }

        double baseRate;
        switch (policy.getType()) {
            case AUTO:
                baseRate = 0.04;
                break;
            case HOME:
                baseRate = 0.005;
                break;
            case HEALTH:
                baseRate = 0.06;
                break;
            case LIFE:
                baseRate = 0.02;
                break;
            default:
                baseRate = 0.03;
                break;
        }

        double ageMultiplier = 1.0;
        if (policy.getHolderAge() < 25) {
            ageMultiplier = 1.35;
        } else if (policy.getHolderAge() > 60) {
            ageMultiplier = 1.25;
        }

        double basePremium = policy.getCoverageAmount() * baseRate;
        double adjustedPremium = basePremium * ageMultiplier * policy.getRiskFactor();

        return Math.round(adjustedPremium * 100.0) / 100.0;
    }
}
