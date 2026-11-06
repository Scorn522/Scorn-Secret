package dev.nekoobfuscator.transforms.jvm.cff;

import java.util.LinkedHashMap;
import java.util.Map;

final class CffIslandMaterialOpDryRunStats {
    private final Map<String, CffIslandMaterialOpDryRunMethodStats> methods =
        new LinkedHashMap<>();

    void record(
        String methodKey,
        int fakeStepRows,
        int poisonStepRows,
        int firstTinyUpdates,
        int secondTinyUpdates,
        int methodKeyUpdates,
        int fakeBounceRows,
        int bouncePredicateRows,
        int denseResultRows,
        int sparseResultRows,
        int hardFailRows
    ) {
        methods.computeIfAbsent(
            methodKey,
            CffIslandMaterialOpDryRunMethodStats::new
        ).record(
            fakeStepRows,
            poisonStepRows,
            firstTinyUpdates,
            secondTinyUpdates,
            methodKeyUpdates,
            fakeBounceRows,
            bouncePredicateRows,
            denseResultRows,
            sparseResultRows,
            hardFailRows
        );
    }

    public Map<String, CffIslandMaterialOpDryRunMethodStats> methods() {
        return methods;
    }
}

final class CffIslandMaterialOpDryRunMethodStats {
    private final String methodKey;
    private int helpers;
    private long fakeStepRows;
    private long poisonStepRows;
    private long firstTinyUpdates;
    private long secondTinyUpdates;
    private long methodKeyUpdates;
    private long fakeBounceRows;
    private long bouncePredicateRows;
    private long denseResultRows;
    private long sparseResultRows;
    private long hardFailRows;
    private int maxFakeStepRows;
    private int maxSecondTinyUpdates;
    private int maxMethodKeyUpdates;
    private int maxBouncePredicateRows;

    CffIslandMaterialOpDryRunMethodStats(String methodKey) {
        this.methodKey = methodKey;
    }

    void record(
        int fakeStepRows,
        int poisonStepRows,
        int firstTinyUpdates,
        int secondTinyUpdates,
        int methodKeyUpdates,
        int fakeBounceRows,
        int bouncePredicateRows,
        int denseResultRows,
        int sparseResultRows,
        int hardFailRows
    ) {
        helpers++;
        this.fakeStepRows += fakeStepRows;
        this.poisonStepRows += poisonStepRows;
        this.firstTinyUpdates += firstTinyUpdates;
        this.secondTinyUpdates += secondTinyUpdates;
        this.methodKeyUpdates += methodKeyUpdates;
        this.fakeBounceRows += fakeBounceRows;
        this.bouncePredicateRows += bouncePredicateRows;
        this.denseResultRows += denseResultRows;
        this.sparseResultRows += sparseResultRows;
        this.hardFailRows += hardFailRows;
        maxFakeStepRows = Math.max(maxFakeStepRows, fakeStepRows);
        maxSecondTinyUpdates = Math.max(maxSecondTinyUpdates, secondTinyUpdates);
        maxMethodKeyUpdates = Math.max(maxMethodKeyUpdates, methodKeyUpdates);
        maxBouncePredicateRows = Math.max(maxBouncePredicateRows, bouncePredicateRows);
    }

    public String methodKey() {
        return methodKey;
    }

    public int helpers() {
        return helpers;
    }

    public long fakeStepRows() {
        return fakeStepRows;
    }

    public long poisonStepRows() {
        return poisonStepRows;
    }

    public long firstTinyUpdates() {
        return firstTinyUpdates;
    }

    public long secondTinyUpdates() {
        return secondTinyUpdates;
    }

    public long methodKeyUpdates() {
        return methodKeyUpdates;
    }

    public long fakeBounceRows() {
        return fakeBounceRows;
    }

    public long bouncePredicateRows() {
        return bouncePredicateRows;
    }

    public long denseResultRows() {
        return denseResultRows;
    }

    public long sparseResultRows() {
        return sparseResultRows;
    }

    public long hardFailRows() {
        return hardFailRows;
    }

    public int maxFakeStepRows() {
        return maxFakeStepRows;
    }

    public int maxSecondTinyUpdates() {
        return maxSecondTinyUpdates;
    }

    public int maxMethodKeyUpdates() {
        return maxMethodKeyUpdates;
    }

    public int maxBouncePredicateRows() {
        return maxBouncePredicateRows;
    }
}

final class CffIslandDryRunStats {
    private final Map<String, CffIslandDryRunMethodStats> methods = new LinkedHashMap<>();
    private int helpers;
    private int trivialCandidates;
    private int denseResultRouters;
    private int sparseResultRouters;
    private int helpersWithFakeCases;
    private int helpersWithMultipleRealBlocks;
    private long realBlocks;
    private long fakeCases;
    private long resultTokens;
    private long dispatchCases;
    private long projectedDispatchRows;
    private long projectedResultRows;
    private long projectedFakeBounceRows;
    private long projectedPoisonRows;
    private long projectedRouterRows;
    private long projectedMaterialRows;
    private long projectedMaterialWords;
    private long projectedCallerDeltaInstructions;
    private long projectedSharedHelperInstructions;
    private long helperInstructions;
    private long callSiteInstructions;
    private long minimumCallerGrowthInstructions;
    private int minHelperInstructions = Integer.MAX_VALUE;
    private int maxHelperInstructions;
    private int maxMinimumCallerGrowthInstructions;
    private int maxRealBlocks;
    private int maxFakeCases;
    private int maxResultTokens;
    private int maxDispatchCases;
    private long maxProjectedMaterialWords;
    private int maxProjectedCallerDeltaInstructions;
    private int maxProjectedSharedHelperInstructions;

    void record(
        String methodKey,
        boolean trivialCandidate,
        int realBlocks,
        int fakeCount,
        boolean denseResultRouter,
        int resultTokens,
        int dispatchCases,
        int helperInstructions,
        int callSiteInstructions,
        int minimumCallerGrowthInstructions,
        int projectedDispatchRows,
        int projectedResultRows,
        int projectedFakeBounceRows,
        int projectedPoisonRows,
        int projectedRouterRows,
        long projectedMaterialRows,
        long projectedMaterialWords,
        int projectedCallerDeltaInstructions,
        int projectedSharedHelperInstructions
    ) {
        helpers++;
        if (trivialCandidate) trivialCandidates++;
        if (denseResultRouter) denseResultRouters++;
        else sparseResultRouters++;
        if (fakeCount > 0) helpersWithFakeCases++;
        if (realBlocks > 1) helpersWithMultipleRealBlocks++;
        this.realBlocks += realBlocks;
        this.fakeCases += fakeCount;
        this.resultTokens += resultTokens;
        this.dispatchCases += dispatchCases;
        this.projectedDispatchRows += projectedDispatchRows;
        this.projectedResultRows += projectedResultRows;
        this.projectedFakeBounceRows += projectedFakeBounceRows;
        this.projectedPoisonRows += projectedPoisonRows;
        this.projectedRouterRows += projectedRouterRows;
        this.projectedMaterialRows += projectedMaterialRows;
        this.projectedMaterialWords += projectedMaterialWords;
        this.projectedCallerDeltaInstructions += projectedCallerDeltaInstructions;
        this.projectedSharedHelperInstructions += projectedSharedHelperInstructions;
        this.helperInstructions += helperInstructions;
        this.callSiteInstructions += callSiteInstructions;
        this.minimumCallerGrowthInstructions += minimumCallerGrowthInstructions;
        minHelperInstructions = Math.min(minHelperInstructions, helperInstructions);
        maxHelperInstructions = Math.max(maxHelperInstructions, helperInstructions);
        maxMinimumCallerGrowthInstructions = Math.max(
            maxMinimumCallerGrowthInstructions,
            minimumCallerGrowthInstructions
        );
        maxRealBlocks = Math.max(maxRealBlocks, realBlocks);
        maxFakeCases = Math.max(maxFakeCases, fakeCount);
        maxResultTokens = Math.max(maxResultTokens, resultTokens);
        maxDispatchCases = Math.max(maxDispatchCases, dispatchCases);
        maxProjectedMaterialWords = Math.max(
            maxProjectedMaterialWords,
            projectedMaterialWords
        );
        maxProjectedCallerDeltaInstructions = Math.max(
            maxProjectedCallerDeltaInstructions,
            projectedCallerDeltaInstructions
        );
        maxProjectedSharedHelperInstructions = Math.max(
            maxProjectedSharedHelperInstructions,
            projectedSharedHelperInstructions
        );
        methods.computeIfAbsent(
            methodKey,
            CffIslandDryRunMethodStats::new
        ).record(
            trivialCandidate,
            realBlocks,
            fakeCount,
            denseResultRouter,
            resultTokens,
            dispatchCases,
            helperInstructions,
            callSiteInstructions,
            minimumCallerGrowthInstructions,
            projectedDispatchRows,
            projectedResultRows,
            projectedFakeBounceRows,
            projectedPoisonRows,
            projectedRouterRows,
            projectedMaterialRows,
            projectedMaterialWords,
            projectedCallerDeltaInstructions,
            projectedSharedHelperInstructions
        );
    }

    public int helpers() {
        return helpers;
    }

    public int trivialCandidates() {
        return trivialCandidates;
    }

    public int denseResultRouters() {
        return denseResultRouters;
    }

    public int sparseResultRouters() {
        return sparseResultRouters;
    }

    public int helpersWithFakeCases() {
        return helpersWithFakeCases;
    }

    public int helpersWithMultipleRealBlocks() {
        return helpersWithMultipleRealBlocks;
    }

    public long helperInstructions() {
        return helperInstructions;
    }

    public long realBlocks() {
        return realBlocks;
    }

    public long fakeCases() {
        return fakeCases;
    }

    public long resultTokens() {
        return resultTokens;
    }

    public long dispatchCases() {
        return dispatchCases;
    }

    public long projectedDispatchRows() {
        return projectedDispatchRows;
    }

    public long projectedResultRows() {
        return projectedResultRows;
    }

    public long projectedFakeBounceRows() {
        return projectedFakeBounceRows;
    }

    public long projectedPoisonRows() {
        return projectedPoisonRows;
    }

    public long projectedRouterRows() {
        return projectedRouterRows;
    }

    public long projectedMaterialRows() {
        return projectedMaterialRows;
    }

    public long projectedMaterialWords() {
        return projectedMaterialWords;
    }

    public long projectedCallerDeltaInstructions() {
        return projectedCallerDeltaInstructions;
    }

    public long projectedSharedHelperInstructions() {
        return projectedSharedHelperInstructions;
    }

    public long callSiteInstructions() {
        return callSiteInstructions;
    }

    public long minimumCallerGrowthInstructions() {
        return minimumCallerGrowthInstructions;
    }

    public int minHelperInstructions() {
        return helpers == 0 ? 0 : minHelperInstructions;
    }

    public int maxHelperInstructions() {
        return maxHelperInstructions;
    }

    public int maxMinimumCallerGrowthInstructions() {
        return maxMinimumCallerGrowthInstructions;
    }

    public int maxRealBlocks() {
        return maxRealBlocks;
    }

    public int maxFakeCases() {
        return maxFakeCases;
    }

    public int maxResultTokens() {
        return maxResultTokens;
    }

    public int maxDispatchCases() {
        return maxDispatchCases;
    }

    public long maxProjectedMaterialWords() {
        return maxProjectedMaterialWords;
    }

    public int maxProjectedCallerDeltaInstructions() {
        return maxProjectedCallerDeltaInstructions;
    }

    public int maxProjectedSharedHelperInstructions() {
        return maxProjectedSharedHelperInstructions;
    }

    public Map<String, CffIslandDryRunMethodStats> methods() {
        return methods;
    }
}

final class CffIslandDryRunMethodStats {
    private final String methodKey;
    private int helpers;
    private int trivialCandidates;
    private int denseResultRouters;
    private int sparseResultRouters;
    private int helpersWithFakeCases;
    private int helpersWithMultipleRealBlocks;
    private long realBlocks;
    private long fakeCases;
    private long resultTokens;
    private long dispatchCases;
    private long projectedDispatchRows;
    private long projectedResultRows;
    private long projectedFakeBounceRows;
    private long projectedPoisonRows;
    private long projectedRouterRows;
    private long projectedMaterialRows;
    private long projectedMaterialWords;
    private long projectedCallerDeltaInstructions;
    private long projectedSharedHelperInstructions;
    private long helperInstructions;
    private long callSiteInstructions;
    private long minimumCallerGrowthInstructions;
    private int minHelperInstructions = Integer.MAX_VALUE;
    private int maxHelperInstructions;
    private int maxMinimumCallerGrowthInstructions;
    private int maxRealBlocks;
    private int maxFakeCases;
    private int maxResultTokens;
    private int maxDispatchCases;
    private long maxProjectedMaterialWords;
    private int maxProjectedCallerDeltaInstructions;
    private int maxProjectedSharedHelperInstructions;

    CffIslandDryRunMethodStats(String methodKey) {
        this.methodKey = methodKey;
    }

    void record(
        boolean trivialCandidate,
        int realBlocks,
        int fakeCount,
        boolean denseResultRouter,
        int resultTokens,
        int dispatchCases,
        int helperInstructions,
        int callSiteInstructions,
        int minimumCallerGrowthInstructions,
        int projectedDispatchRows,
        int projectedResultRows,
        int projectedFakeBounceRows,
        int projectedPoisonRows,
        int projectedRouterRows,
        long projectedMaterialRows,
        long projectedMaterialWords,
        int projectedCallerDeltaInstructions,
        int projectedSharedHelperInstructions
    ) {
        helpers++;
        if (trivialCandidate) trivialCandidates++;
        if (denseResultRouter) denseResultRouters++;
        else sparseResultRouters++;
        if (fakeCount > 0) helpersWithFakeCases++;
        if (realBlocks > 1) helpersWithMultipleRealBlocks++;
        this.realBlocks += realBlocks;
        this.fakeCases += fakeCount;
        this.resultTokens += resultTokens;
        this.dispatchCases += dispatchCases;
        this.projectedDispatchRows += projectedDispatchRows;
        this.projectedResultRows += projectedResultRows;
        this.projectedFakeBounceRows += projectedFakeBounceRows;
        this.projectedPoisonRows += projectedPoisonRows;
        this.projectedRouterRows += projectedRouterRows;
        this.projectedMaterialRows += projectedMaterialRows;
        this.projectedMaterialWords += projectedMaterialWords;
        this.projectedCallerDeltaInstructions += projectedCallerDeltaInstructions;
        this.projectedSharedHelperInstructions += projectedSharedHelperInstructions;
        this.helperInstructions += helperInstructions;
        this.callSiteInstructions += callSiteInstructions;
        this.minimumCallerGrowthInstructions += minimumCallerGrowthInstructions;
        minHelperInstructions = Math.min(minHelperInstructions, helperInstructions);
        maxHelperInstructions = Math.max(maxHelperInstructions, helperInstructions);
        maxMinimumCallerGrowthInstructions = Math.max(
            maxMinimumCallerGrowthInstructions,
            minimumCallerGrowthInstructions
        );
        maxRealBlocks = Math.max(maxRealBlocks, realBlocks);
        maxFakeCases = Math.max(maxFakeCases, fakeCount);
        maxResultTokens = Math.max(maxResultTokens, resultTokens);
        maxDispatchCases = Math.max(maxDispatchCases, dispatchCases);
        maxProjectedMaterialWords = Math.max(
            maxProjectedMaterialWords,
            projectedMaterialWords
        );
        maxProjectedCallerDeltaInstructions = Math.max(
            maxProjectedCallerDeltaInstructions,
            projectedCallerDeltaInstructions
        );
        maxProjectedSharedHelperInstructions = Math.max(
            maxProjectedSharedHelperInstructions,
            projectedSharedHelperInstructions
        );
    }

    public String methodKey() {
        return methodKey;
    }

    public int helpers() {
        return helpers;
    }

    public int trivialCandidates() {
        return trivialCandidates;
    }

    public int denseResultRouters() {
        return denseResultRouters;
    }

    public int sparseResultRouters() {
        return sparseResultRouters;
    }

    public int helpersWithFakeCases() {
        return helpersWithFakeCases;
    }

    public int helpersWithMultipleRealBlocks() {
        return helpersWithMultipleRealBlocks;
    }

    public long helperInstructions() {
        return helperInstructions;
    }

    public long realBlocks() {
        return realBlocks;
    }

    public long fakeCases() {
        return fakeCases;
    }

    public long resultTokens() {
        return resultTokens;
    }

    public long dispatchCases() {
        return dispatchCases;
    }

    public long projectedDispatchRows() {
        return projectedDispatchRows;
    }

    public long projectedResultRows() {
        return projectedResultRows;
    }

    public long projectedFakeBounceRows() {
        return projectedFakeBounceRows;
    }

    public long projectedPoisonRows() {
        return projectedPoisonRows;
    }

    public long projectedRouterRows() {
        return projectedRouterRows;
    }

    public long projectedMaterialRows() {
        return projectedMaterialRows;
    }

    public long projectedMaterialWords() {
        return projectedMaterialWords;
    }

    public long projectedCallerDeltaInstructions() {
        return projectedCallerDeltaInstructions;
    }

    public long projectedSharedHelperInstructions() {
        return projectedSharedHelperInstructions;
    }

    public long callSiteInstructions() {
        return callSiteInstructions;
    }

    public long minimumCallerGrowthInstructions() {
        return minimumCallerGrowthInstructions;
    }

    public int minHelperInstructions() {
        return helpers == 0 ? 0 : minHelperInstructions;
    }

    public int maxHelperInstructions() {
        return maxHelperInstructions;
    }

    public int maxMinimumCallerGrowthInstructions() {
        return maxMinimumCallerGrowthInstructions;
    }

    public int maxRealBlocks() {
        return maxRealBlocks;
    }

    public int maxFakeCases() {
        return maxFakeCases;
    }

    public int maxResultTokens() {
        return maxResultTokens;
    }

    public int maxDispatchCases() {
        return maxDispatchCases;
    }

    public long maxProjectedMaterialWords() {
        return maxProjectedMaterialWords;
    }

    public int maxProjectedCallerDeltaInstructions() {
        return maxProjectedCallerDeltaInstructions;
    }

    public int maxProjectedSharedHelperInstructions() {
        return maxProjectedSharedHelperInstructions;
    }
}

