# KnownUser.V3.Cloudflare
The Queue-it Security Framework is used to ensure that end users cannot reach to your protected backend routes without passing the virtual queue by performing a server-side validation before processing a request. This approach is using [Cloudflare Workers](https://developers.cloudflare.com/workers/] ) and [Cloudflare Workers KV](https://developers.cloudflare.com/workers/kv/) to integrate a Cloudflare protected WebServer with [Queue-it](https://queue-it.com/). This repository is containing a JavaScript file `queueitknownuser.bundle.js` you add as a Worker to your Cloudflare distribution to protect your traffic going through Cloudflare. 
## Introduction
When a user makes a request to your backend Cloudflare will trigger queue-it Worker, the  script validates the request and if it is needed, it will redirect the user to the queue. After waiting in the queue, the queue engine will redirect the user back to your end attaching a query string parameter (`queueittoken`) containing some information about the user to the URL.
The most important fields of the `queueittoken` are:

- q - the users' unique queue identifier
- ts - a timestamp of how long this redirect is valid
- h - a hash of the token

After the user is returned from the queue, the Worker script will let the user continue his request to your backend (without redirecting to the queue since the request has a valid queueittoken as querystring).

## Instruction
*  Browse to Cloudflare dashboard -> Workers -> Workers KV and add a new KV, name it `IntegrationConfigKV`
*  Download and unzip the `worker.zip` file from the latest release.
*  Browse to  Cloudflare dashboard -> Workers -> Launch Editor -> Add script and paste the `queueitknownuser.bundle.js` file. 
*  Go to the added script select the Resources tab -> KV Namespaces click Add Binding and for VARIABLE NAME enter `IntegrationConfigKV` and for NAMESPACE you should be able to select `IntegrationConfigKV` which you had added before
*  Add routes you need to be protected by Queue-it (e.g. PROTECTED.YOURDOMAIN.COM/*)
*  Search for `QUEUEIT_CUSTOMERID` and `QUEUEIT_SECRETKEY` in `queueitknownuser.bundle.js` replace their values with your customerId and secretKey found in Go Queue-It self-service platform (I have done it for you in the attached file, so it is not needed here)
*  Setup the Publish web endpoint (e.g. PROTECTED.YOURDOMAIN.COM/?_push_queueit_config)  in Integration -> Overview -> Settings 
*  Setup Trigger and Action in Go Queue-it and once ready click Integration -> Overview -> Show/Hide Instructions and click the Push Now button
>Please contact [queue-it support](https://support.queue-it.com/hc/en-us) for further information and instructions.
 