package com.codeguard.policy;

import java.util.Objects;

/**
 * Represents an insurance policy.
 */
public class Policy {
    public enum PolicyType {
        AUTO,
        HOME,
        HEALTH,
        LIFE
    }

    private final String id;
    private final String holderName;
    private final int holderAge;
    private final PolicyType type;
    private final double coverageAmount;
    private final double riskFactor;

    public Policy(
            String id,
            String holderName,
            int holderAge,
            PolicyType type,
            double coverageAmount,
            double riskFactor) {
        if (id == null || id.isBlank()) {
            throw new IllegalArgumentException("Policy ID must not be blank");
        }
        if (holderAge < 18 || holderAge > 120) {
            throw new IllegalArgumentException("Holder age must be between 18 and 120");
        }
        if (coverageAmount <= 0) {
            throw new IllegalArgumentException("Coverage amount must be positive");
        }
        if (riskFactor < 0.5 || riskFactor > 3.0) {
            throw new IllegalArgumentException("Risk factor must be between 0.5 and 3.0");
        }
        this.id = id;
        this.holderName = holderName;
        this.holderAge = holderAge;
        this.type = Objects.requireNonNull(type, "PolicyType must not be null");
        this.coverageAmount = coverageAmount;
        this.riskFactor = riskFactor;
    }

    public String getId() {
        return id;
    }

    public String getHolderName() {
        return holderName;
    }

    public int getHolderAge() {
        return holderAge;
    }

    public PolicyType getType() {
        return type;
    }

    public double getCoverageAmount() {
        return coverageAmount;
    }

    public double getRiskFactor() {
        return riskFactor;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof Policy policy)) {
            return false;
        }
        return Objects.equals(id, policy.id);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id);
    }
}
