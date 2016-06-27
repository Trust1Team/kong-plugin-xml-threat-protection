---
id: page-plugin
title: Plugins - XML Threat Protection
header_title: XML Threat Protection
header_icon: /assets/images/icons/plugins/xmlthreadprotection.png
breadcrumbs:
  Plugins: /plugins
nav:
  - label: Getting Started
  - label: Usage
    items:
      - label: Terminology
      - label: Configuration
---

Address XML vulnerabilities and minimize attacks on your API. Optionally, detect XML payload attacks based on configured limits. Screen against XML threats using the following approaches:

* Validate messages against an XML schema (.xsd)
* Evaluate message content for specific blacklisted keywords or patterns
* Detect corrupt or malformed messages before those messages are parsed

----

## Terminology

- `API`: your upstream service, for which Kong proxies requests to.
- `Plugin`: a plugin executes actions inside Kong during the request/response lifecycle.

----

## Configuration

Configuring the plugin is straightforward, you can add it on top of an [API][api-object] by executing the following request on your Kong server:

```bash
$ curl -X POST http://kong:8001/apis/{api}/plugins \
--data "name=xml-threat-protection"
```

`api`: The `id` or `name` of the API that this plugin configuration will target

form parameter            | required     | description
---                       | ---          | ---
`name`                    | *required*   | The name of the plugin to use, in this case: `xml-threat-protection`

----


