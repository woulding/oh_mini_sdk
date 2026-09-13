# I. Histogram Logging Guide

## 1. Define Useful Metrics  
### 1.1 Measure What You Care About Directly  
   The best practice is usually to measure what you truly care about directly. For example, suppose you want to measure the running time of a function that simply calls two sub-functions, both of which have already been instrumented with histograms. You might think you can add the histograms of these two sub-functions to get the total time, but this could lead to misleading results. If we could know which call each logged data point came from, we could pair them to calculate the total time. However, histograms are pre-aggregated on the client side, meaning it's impossible to recover which points should be paired. Adding two histograms is equivalent to assuming they are independent, which may not be true in practice.  
   ### 1.2 Provide Context  
   When defining new metrics, consider in advance how the data will be analyzed. In many cases, context is needed to make the data interpretable.  
   ### 1.3 Name Histograms  
   Histograms use dots (<span style="color:#e60000;">.</span>) as separators to organize by category. Names should follow formats like <span style="color:#e60000;">KitName.Name</span> or <span style="color:#e60000;">KitName.Category.Name</span>, where each category groups related histograms.  
   New top-level categories should not be introduced lightly. If you wish to do so, first check if existing categories already cover your metric.  

## 2. Choose Histogram Type  
   Subsystems can choose different histogram types for logging based on their scenarios.  
   | Histogram Type | Interface Definition | Description | Use Case |  
   |--|--|--|--|  
   | Boolean Histogram | #define HISTOGRAM_BOOLEAN(name, sample) | Records binary events, such as whether an operation occurred | HISTOGRAM_BOOLEAN("ArkUI.APICall.createLongPressGesture", isCalled) |  
   | Enumeration Histogram | #define HISTOGRAM_ENUMERATION(name, sample, boundary) | Records enumeration values like user behaviors or operation types | HISTOGRAM_ENUMERATION("ArkUI.ErrorCode.createLongPressGesture", ARKUI_ERROR_CODE_PARAM_ERROR, ArkUIErrorCode::kMaxValue) |  
   | Count Histogram | #define HISTOGRAM_CUSTOM_COUNTS(name, sample, min, max, bucket_count) | Records count data over a large range | HISTOGRAM_CUSTOM_COUNTS("ArkUI.Button.click", 3, 1, 100, 10) |  
   | Time Histogram | #define HISTOGRAM_TIMES(name, sample) | Records time intervals in ms, such as long-press duration | HISTOGRAM_TIMES("ArkUI.Button.longPress", 2) |  
   | Percentage Histogram | #define HISTOGRAM_PERCENTAGE(name, sample) | Records percentages, such as completion rates | HISTOGRAM_PERCENTAGE("ArkUI.ImageCompression.Ratio", compression_ratio_percentage) |  

   ### 2.1 Boolean Histogram  
   Boolean histograms are suitable for analyzing binary events, such as whether an API was called and its call count.  

   ### 2.2 Enumeration Histogram  
   Enumeration histograms are suitable for joint analysis of a set of related states. For example, API call return error codes are well-suited for enumeration histograms.  
   If the total count of the histogram (sum of all buckets) is meaningful, it usually indicates that an enumeration histogram is appropriate.  
   Enumeration histograms are also suitable for counting events, such as counting occurrences of different error codes returned by API calls.  

   ### 2.3 Count Histogram  
   Count histograms require manual selection of min, max, and bucket count; choose these numbers carefully based on the recommendations below.  
   Choosing Min and Max Values  
   The max value should ensure that few samples exceed it. If a sample value >= max, it falls into the "overflow bucket." If the overflow bucket is too large, analysis becomes difficult. Empirically, the overflow bucket should ideally account for <= 1% (the smaller, the better), allowing analysis up to the 99th percentile. It's better to err on the side of a slightly larger range than too small. If set incorrectly, it can only be fixed in the next release cycle.  
   Min Value: If you care about all possible values (including 0), use 1. All histograms have an underflow bucket for 0, so min=1 is appropriate. Otherwise, use a min value suitable for your scenario.  
   Choosing Bucket Count  
   Choose the minimum number of buckets that meet granularity needs. Count histogram bucket sizes increase exponentially by default, providing finer granularity for small values and reasonable resolution for large values. The macro defaults to 50 buckets (100 for large ranges), which is usually sufficient. Histograms pre-allocate all buckets, so the bucket count directly affects memory usage. Do not exceed 100 buckets without strong justification.  

   ### 2.4 Time Histogram  
   Time histograms can record function call durations (TimeDelta).  

   ### 2.5 Percentage Histogram  
   Percentage histograms record any ratio (with equal-width buckets).  

## 3. Histogram Lifecycle  
   ### 3.1 Adding a Histogram  
   Step One: Define Useful Metrics  
   Measure precisely what you want and plan ahead.  
   - Why do we need this metric?  
   - When is this metric emitted?  
   - What value does this metric provide?  
   - After viewing charts in the dashboard, what improvements can be made?  
   - Why do we need this metric?  
   	    - Track how users exit the feedback application.  
   - When is this metric emitted?  
   		- Triggered when a user closes the feedback app.  
   - What value does this metric provide?  
   		- Determine submission vs. cancellation rates.  
   		- Identify where users drop off in the process.  
   - After viewing the data, what improvements can be made?  
   		- If kQuitNoHelpContentClicked values are high -> This may indicate that help content is not useful, so improve the quality of help articles.  
   		- If kQuitNoResultFound (offline or search feature disabled) values are high -> Improve search reliability, remind users to stay online when submitting feedback, etc.  
  
   Step Two: Create the Metric  
   Choose a histogram type; common types include:  
   Enumeration Histogram  
   Boolean Histogram  
   Time Histogram  
   Add your histogram in the histograms.xml file.  
   For example, TestEnum would be an enumeration histogram.  
For enumeration types, also add an enum value.  
```
<enum name="TestEnum">  
  <int value="0" label="kQuitSearchPageHelpContentClicked"/>  
  <int value="1" label="kQuitSearchPageNoHelpContentClicked"/>  
  <int value="2" label="kQuitNoResultFound"/>  
  <int value="3" label="kQuitShareDataPageHelpContentClicked"/>  
  <int value="4" label="kQuitShareDataPageNoHelpContentClicked"/>  
  <int value="5" label="kSuccessHelpContentClicked"/>  
  <int value="6" label="kSuccessNoHelpContentClicked"/>  
</enum>  
```
Call the logging function in histogram_util.cc.  
```
void EmitFeedbackAppExitPath(mojom::FeedbackAppExitPath exit_path) {  
    HISTOGRAM_ENUMERATION(kFeedbackAppExitPath, exit_path);  
}  
```

### 3.2 Modifying a Histogram  
When modifying the semantics of a histogram (e.g., when it is generated, what buckets represent, bucket ranges or counts for numerical histograms), create a new histogram with a new name. If users won't move between buckets and bucket proportions aren't meaningful, adding new values to an enum doesn't require a new histogram name. Otherwise, mixing data before and after changes can lead to misleading analysis.  
In some cases, changes to histograms are allowed even if semantics haven't changed at all. Examples of allowed changes:  
- Rewriting histogram summaries for greater accuracy.  
- Enum bucket labels can be changed as long as they still refer to the same thing.  

### 3.3 Deprecating a Histogram  
Deprecation Notes  
Specify expiration in the histogram description in histograms.xml using the expires_after attribute, which is mandatory. Use YYYY-MM-DD date format or milestone format (e.g., API7.0.1).  
After expiration, code that logs this histogram becomes dead code and should be removed from the codebase; also clean up entries in histograms.xml.  
In rare cases, expiration can be set to never for critical metrics (typically used in other reports).  
Common Scenario Recommendations  
- If the owner moves to another project, find a new owner.  
- If neither the owner nor the team uses the histogram anymore, delete it.  
- If not currently used but might be in the future, delete it.  
- If not currently used but might be soon, set expiration to ~3 months.  
- Otherwise, set a reasonable expiration time, no longer than 1 year.  
Conclusion: If a histogram is being viewed, it should automatically extend without developer intervention.  
How to Choose Expiration for New Histograms  
Generally, choose a reasonable usage period, no longer than 1 year.  
Common Cases:  
- For evaluating new feature launches, align expiration with expected launch time.  
- If the histogram is expected to be useful long-term, set expiration to no more than 1 year for later reassessment.  
- Otherwise, typically set 3-6 months.  

### 3.4 Deleting a Histogram  
Delete code related to histograms that are no longer needed, as histograms consume memory.  

## 4. High-Performance Logging  
In most cases, you don't need to worry about histogram logging performance (our tests show less than 1us).  
However, if you're logging histograms in performance-critical or "hotspot" code where total count isn't important (e.g., measuring latency or ratios), consider:  
if ( base :: ShouldRecordSubsampledMetric ( 0.01 )) {  
    HISTOGRAM_TIMES ( "Component.Feature.Duration.Subsampled" , timer->Elapsed ());  
}  
For example, this optimization can be applied to histograms logged every frame.  

## 5. Testing Histograms  
### 5.1 Local Testing  
Enter hdc shell and use the command line to export histogram logging data.  
hidumper -s 66568 -a all  

### 5.2 End-to-End Remote Testing  
HA collects data and reports to the test environment for data viewing.  

II. Reviewing Histograms  

1. How to Become a Reviewer  
API Committers are default reviewers for logging items in their domains.  

## 2. Review Standards  
### 2.1 Security and Privacy  
Logged data is anonymous and aggregated, not traceable to individual users, so existing HA protocols cover this.  
### 2.2 Correctness  
Is the histogram recorded correctly?  
Check for errors and unused buckets.  
Is the bucket layout efficient? Typically, if the number of buckets exceeds 50, it should be challenged.  
For timing metrics, is the min-max range reasonable for the measured duration?  

### 2.3 Sustainability  
Is the number of added metrics/buckets reasonable?  
While there's no hard rule, anything over 20 independent histograms should be escalated.  
Any histogram with over 100 possible buckets should be escalated.  
Is the validity period set reasonably?  

# III. Logging Principles  

## 1. Mandatory Logging for High-Value Features  
High-value features (e., flash control functionality, font management) require business-driven logging (feature usage tracking) to monitor operational activities and feature utilization.
## 2. Log Error Codes and Failure Rates as Needed  
## 3. For performance monitoring, security, and change deprecation needs, log as required; used to collect performance data and reference data for interface changes/deprecations.  
## 4. For high-performance interfaces (potentially high-frequency calls, e.g., per-frame), use business-driven logging cautiously.  

# IV. FAQ  

## Q1: Will a large number of interfaces reaching the logging limit?  
Control to 5000-6000 logging items.  

## Q2: Interface performance?  
Local tests show less than 1us; under normal conditions, it can reach ns.  

## Q3: From an information statistics perspective, does framework-reported information include: device, version, app info, interface (logging item)?  
Statistics by logging item, beta, feature dashboard; can filter by device, version, app info.  
For high-frequency interfaces: Provide sampling rate settings, e.g., log once per 100 calls.  

## Q4: Are logging interfaces the same for different types? E.g., performance logging—each performance varies, how to count? Error codes are similar.  
getWindow [0-100ms]: 11 times, [100-200]: 23 times, [1000-infinity].  
There are fixed and configurable bins.  

## Q5: What is the division of labor between the two sets of logging interfaces? If Hisysevent is logged, is it still necessary to log in new features?  
The new architecture leans towards statistically significant logging.  

## Q6: Does the dashboard need to be self-configured?  
Data format is unified; there will be a unified histogram dashboard. Can filter by version, device, etc.
