package com.codeguard.policy.bad;

import java.util.LinkedList;

public class BadPolicyService {
    // Fake credentials for testing scanner
    private static final String AWS_ACCESS_KEY="AKIAIOSFODNN7EXAMPLE";

public void processBadPolicy(String policyType){
        // Bad formatting, System.out.println, == on string, TODO
        // TODO: refactor this entire method
System.out.println("Processing: "+policyType);

        if(policyType=="AUTO"){
            try{
                performAutoCalculation();
            }catch(Exception e){
                // Empty catch block anti-pattern
            }
        }
}

    private void performAutoCalculation() {
        try {
            int x = 10 / 0;
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
