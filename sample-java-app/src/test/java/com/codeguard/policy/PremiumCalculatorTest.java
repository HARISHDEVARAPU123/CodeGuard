package com.codeguard.policy;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

class PremiumCalculatorTest {

    private PremiumCalculator calculator;

    @BeforeEach
    void setUp() {
        calculator = new PremiumCalculator();
    }

    @Test
    @DisplayName("Calculate premium for standard adult auto policy")
    void testStandardAutoPolicy() {
        Policy policy = new Policy("POL-101", "Alice Smith", 35, Policy.PolicyType.AUTO, 25000.0, 1.0);
        double premium = calculator.calculatePremium(policy);
        assertEquals(1000.0, premium);
    }

    @Test
    @DisplayName("Calculate premium for young driver with higher risk")
    void testYoungDriverHighRisk() {
        Policy policy = new Policy("POL-102", "Bob Jones", 21, Policy.PolicyType.AUTO, 20000.0, 1.5);
        // base = 20000 * 0.04 = 800; adjusted = 800 * 1.35 * 1.5 = 1620.0
        double premium = calculator.calculatePremium(policy);
        assertEquals(1620.0, premium);
    }

    @Test
    @DisplayName("Calculate premium for senior home insurance")
    void testSeniorHomePolicy() {
        Policy policy = new Policy("POL-103", "Carol White", 65, Policy.PolicyType.HOME, 300000.0, 1.0);
        // base = 300000 * 0.005 = 1500; adjusted = 1500 * 1.25 * 1.0 = 1875.0
        double premium = calculator.calculatePremium(policy);
        assertEquals(1875.0, premium);
    }

    @Test
    @DisplayName("Calculate premium for health policy")
    void testHealthPolicy() {
        Policy policy = new Policy("POL-104", "David Brown", 40, Policy.PolicyType.HEALTH, 50000.0, 1.2);
        // base = 50000 * 0.06 = 3000; adjusted = 3000 * 1.0 * 1.2 = 3600.0
        double premium = calculator.calculatePremium(policy);
        assertEquals(3600.0, premium);
    }

    @Test
    @DisplayName("Calculate premium for life policy")
    void testLifePolicy() {
        Policy policy = new Policy("POL-105", "Emma Green", 30, Policy.PolicyType.LIFE, 200000.0, 0.8);
        // base = 200000 * 0.02 = 4000; adjusted = 4000 * 1.0 * 0.8 = 3200.0
        double premium = calculator.calculatePremium(policy);
        assertEquals(3200.0, premium);
    }

    @Test
    @DisplayName("Throw exception for null policy")
    void testNullPolicyThrows() {
        assertThrows(IllegalArgumentException.class, () -> calculator.calculatePremium(null));
    }

    @Test
    @DisplayName("Throw exception for invalid policy parameters")
    void testInvalidPolicyParameters() {
        assertThrows(IllegalArgumentException.class, () ->
                new Policy("", "Invalid", 30, Policy.PolicyType.AUTO, 10000.0, 1.0));
        assertThrows(IllegalArgumentException.class, () ->
                new Policy("POL-999", "Too Young", 16, Policy.PolicyType.AUTO, 10000.0, 1.0));
        assertThrows(IllegalArgumentException.class, () ->
                new Policy("POL-999", "Zero Coverage", 30, Policy.PolicyType.AUTO, 0.0, 1.0));
    }

    @Test
    @DisplayName("Policy equality and getters work properly")
    void testPolicyProperties() {
        Policy p1 = new Policy("POL-001", "User One", 28, Policy.PolicyType.AUTO, 15000.0, 1.0);
        Policy p2 = new Policy("POL-001", "User One Copy", 28, Policy.PolicyType.AUTO, 15000.0, 1.0);
        assertEquals(p1, p2);
        assertEquals(p1.hashCode(), p2.hashCode());
        assertEquals("POL-001", p1.getId());
        assertEquals("User One", p1.getHolderName());
        assertNotNull(p1.getType());
    }
}
