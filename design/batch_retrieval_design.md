# Batch retrieval design

This document will cover the options for enhancing Batch Retrieval requests.

### Motivation

*Previously*, for the init container solution, each Secrets Provider was sitting within the same Deployment as the app. Because of this, when a batch retrieval request was made, the requests were dispersed across many call to the Conjur server. If one K8s Secret was not able to be updated with a Conjur value (for example due to a permission error), then the batch request would fail and only that pod would not spin up successfully. 

*Now* that the Secrets Provider is outside, a single batch retrieval request will be made to Conjur for *all* application. So if there is a failure in receiving one of the values, then the whole request would fail. In other words, **no application** will spin up in the namespace.

|      | Solution                                                     | Pros                                                         | Cons                                                         | Effort (T-shirt size) |
| ---- | ------------------------------------------------------------ | ------------------------------------------------------------ | ------------------------------------------------------------ | --------------------- |
| 1    | *Client side:* <br />For each K8s Secret, perform a new Batch request | - No server side changes / no breaking changes               | Load on server with extra calls (*)                          | S, 5 days             |
| 2    | *Server side:*<br />Update Batch retrieval to return list of variables **and** their response (success/failure) (**) | - Will help us during rotation for Milestone 2<br />- Better / straightforward design for how batch endpoints | - Requires both client/server implementation<br />- Need to handle backwards compatibility | M, 10 days            |
| 3    | Stay as is                                                   | No additional work needed                                    | Bad UX                                                       | -                     |

(*) Fallback solution: use this solution as a safety net, only if the original Batch Retrieval request fails

(**) This solution can be broken up in two: 1. Create a new API endpoint or 2. use existing one (return 409 response)
