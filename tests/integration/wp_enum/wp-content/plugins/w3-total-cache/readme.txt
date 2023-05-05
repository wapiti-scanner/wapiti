=== Plugin Name ===
Contributors: boldgrid, fredericktownes, maxicusc, gidomanders, bwmarkle, harryjackson1221, joemoto, vmarko, jacobd91
Tags: seo, cache, CDN, pagespeed, caching, performance, compression, optimize, cloudflare, nginx, apache, varnish, redis, aws, amazon web services, s3, cloudfront, azure
Requires at least: 5.3
Tested up to: 6.2
Stable tag: 2.3.1
License: GPLv2 or later
License URI: http://www.gnu.org/licenses/gpl-2.0.html

Search Engine (SEO) &amp; Performance Optimization (WPO) via caching. Integrated caching: CDN, Page, Minify, Object, Fragment, Database support.

== Description ==

W3 Total Cache (W3TC) improves the SEO, Core Web Vitals and overall user experience of your site by increasing website performance and reducing load times by leveraging features like content delivery network (CDN) integration and the latest best practices.

W3TC is the **only** web host agnostic Web Performance Optimization (WPO) framework for WordPress trusted by millions of publishers, web developers, and web hosts worldwide for more than a decade. It is the total performance solution for optimizing WordPress Websites.

An inside look:

https://youtu.be/7AsNSSrZq4Y

*BENEFITS*

* Improvements in search engine result page rankings, especially for mobile-friendly websites and sites that use SSL
* At least 10x improvement in overall site performance (Grade A in [WebPagetest](https://www.webpagetest.org/) or significant [Google PageSpeed](http://code.google.com/speed/page-speed/) improvements) **when fully configured**
* Improved conversion rates and "[site performance](http://googlewebmastercentral.blogspot.com/2009/12/your-sites-performance-in-webmaster.html)" which [affect your site's rank](http://googlewebmastercentral.blogspot.com/2010/04/using-site-speed-in-web-search-ranking.html) on Google.com
* "Instant" repeat page views: browser caching
* Optimized progressive render: pages start rendering quickly and can be interacted with more quickly
* Reduced page load time: increased visitor time on site; visitors view more pages
* Improved web server performance; sustain high traffic periods
* Up to 80% bandwidth savings when you minify HTML, minify CSS and minify JS files.

*KEY FEATURES*

* Compatible with shared hosting, virtual private / dedicated servers and dedicated servers / clusters
* Transparent content delivery network (CDN) management with Media Library, theme files and WordPress itself
* Mobile support: respective caching of pages by referrer or groups of user agents including theme switching for groups of referrers or user agents
* Accelerated Mobile Pages (AMP) support
* Secure Socket Layer (SSL/TLS) support
* Caching of (minified and compressed) pages and posts in memory or on disk or on (FSD) CDN (by user agent group)
* Caching of (minified and compressed) CSS and JavaScript in memory, on disk or on CDN
* Caching of feeds (site, categories, tags, comments, search results) in memory or on disk or on CDN
* Caching of search results pages (i.e. URIs with query string variables) in memory or on disk
* Caching of database objects in memory or on disk
* Caching of objects in memory or on disk
* Caching of fragments in memory or on disk
* Caching methods include local Disk, Redis, Memcached, APC, APCu, eAccelerator, XCache, and WinCache
* Minify CSS, Minify JavaScript and Minify HTML with granular control
* Minification of posts and pages and RSS feeds
* Minification of inline, embedded or 3rd party JavaScript with automated updates to assets
* Minification of inline, embedded or 3rd party CSS with automated updates to assets
* Defer non critical CSS and Javascript for rendering pages faster than ever before
* Defer offscreen images using Lazy Load to improve the user experience
* Browser caching using cache-control, future expire headers and entity tags (ETag) with "cache-busting"
* JavaScript grouping by template (home page, post page etc) with embed location control
* Non-blocking JavaScript embedding
* Import post attachments directly into the Media Library (and CDN)
* Leverage our multiple CDN integrations to optimize images
* WP-CLI support for cache purging, query string updating and more
* Various security features to help ensure website safety
* Caching statistics for performance insights of any enabled feature
* Extension framework for customization or extensibility for Cloudflare, WPML and much more
* Reverse proxy integration via Nginx or Varnish
* Image Service API extension provides WebP image format conversion from common image formats (on upload and on demand)

Speed up your site tremendously, improve core web vitals and the overall user experience for your visitors without having to change your WordPress host, theme, plugins or your content production workflow.

== Frequently Asked Questions ==

= Why does speed matter? =

Search engines like Google, measure and factor in the speed of web sites in their ranking algorithm. When they recommend a site they want to make sure users find what they're looking for quickly. So in effect you and Google should have the same objective.

Speed is among the most significant success factors web sites face. In fact, your site's speed directly affects your income (revenue) &mdash; it's a fact. Some high traffic sites conducted research and uncovered the following:

* Google.com: **+500 ms** (speed decrease) -> **-20% traffic loss** [[1](http://home.blarg.net/~glinden/StanfordDataMining.2006-11-29.ppt)]
* Yahoo.com: **+400 ms** (speed decrease) -> **-5-9% full-page traffic loss** (visitor left before the page finished loading) [[2](http://www.slideshare.net/stoyan/yslow-20-presentation)]
* Amazon.com: **+100 ms** (speed decrease) -> **-1% sales loss** [[1](http://home.blarg.net/~glinden/StanfordDataMining.2006-11-29.ppt)]

A thousandth of a second is not a long time, yet the impact is quite significant. Even if you're not a large company (or just hope to become one), a loss is still a loss. W3 Total Cache is your solution for faster websites, happier visitors and better results.

Many of the other consequences of poor performance were discovered more than a decade ago:

* Lower perceived credibility (Fogg et al. 2001)
* Lower perceived quality (Bouch, Kuchinsky, and Bhatti 2000)
* Increased user frustration (Ceaparu et al. 2004)
* Increased blood pressure (Scheirer et al. 2002)
* Reduced flow rates (Novak, Hoffman, and Yung 200)
* Reduced conversion rates (Akamai 2007)
* Increased exit rates (Nielsen 2000)
* Are perceived as less interesting (Ramsay, Barbesi, and Preece 1998)
* Are perceived as less attractive (Skadberg and Kimmel 2004)

There are a number of [resources](http://www.websiteoptimization.com/speed/tweak/psychology-web-performance/) that have been documenting the role of performance in success on the web, W3 Total Cache exists to give you a framework to tune your application or site without having to do years of research.

= Why is W3 Total Cache better than other caching solutions? =

**It's a complete framework.** Most cache plugins available do a great job at achieving a couple of performance gains. Total Cache is different because it remedies numerous performance reducing aspects of any web site. It goes farther than the basics, beyond merely reducing CPU usage (load) or bandwidth consumption for HTML pages. Equally important, the plugin requires no theme modifications, modifications to your .htaccess (mod_rewrite rules) or programming compromises to get started. Most importantly, it's the only plugin designed to optimize all practical hosting environments small or large. The options are many and setup is easy.

= I've never heard of any of this stuff; my site is fine, no one complains about the speed. Why should I install this? =

Rarely do readers take the time to complain. They typically just stop browsing earlier than you'd prefer and may not return altogether. This is the only plugin specifically designed to make sure that all aspects of your site are as fast as possible. Google is placing more emphasis on the [speed of a site as a factor in rankings](http://searchengineland.com/site-speed-googles-next-ranking-factor-29793); this plugin helps with that too.

It's in every web site owner's best interest is to make sure that the performance of your site is not hindering its success.

= Which WordPress versions are supported? =

To use all features in the suite, a minimum of version WordPress 3.8 with PHP 5.6 is required. Earlier versions will benefit from our Media Library Importer to get them back on the upgrade path and into a CDN of their choosing.

= Why doesn't minify work for me? =

Great question. W3 Total Cache uses several open source tools to attempt to combine and optimize CSS, JavaScript and HTML etc. Unfortunately some trial and error is required on the part of developers is required to make sure that their code can be successfully minified with the various libraries W3 Total Cache supports. Even still, if developers do test their code thoroughly, they cannot be sure that interoperability with other code your site may have. This fault does not lie with any single party here, because there are thousands of plugins and theme combinations that a given site can have, there are millions of possible combinations of CSS, JavaScript etc.

A good rule of thumb is to try auto mode, work with a developer to identify the code that is not compatible and start with combine only mode (the safest optimization) and increase the optimization to the point just before functionality (JavaScript) or user interface / layout (CSS) breaks in your site.

We're always working to make this more simple and straight forward in future releases, but this is not an undertaking we can realize on our own. When you find a plugin, theme or file that is not compatible with minification reach out to the developer and ask them either to provide a minified version with their distribution or otherwise make sure their code is minification-friendly.

= What about comments? Does the plugin slow down the rate at which comments appear? =

On the contrary, as with any other action a user can perform on a site, faster performance will encourage more of it. The cache is so quickly rebuilt in memory that it's no trouble to show visitors the most current version of a post that's experiencing Digg, Slashdot, Drudge Report, Yahoo Buzz or Twitter effect.

= Will the plugin interfere with other plugins or widgets? =

No, on the contrary if you use the minify settings you will improve their performance by several times.

= Does this plugin work with WordPress in network mode? =

Indeed it does.

= Does this plugin work with BuddyPress (bbPress)? =

Yes.

= Will this plugin speed up WP Admin? =

Yes, indirectly - if you have a lot of bloggers working with you, you will find that it feels like you have a server dedicated only to WP Admin once this plugin is enabled; the result, increased productivity.

= Which web servers do you support? =

We are aware of no incompatibilities with [apache](http://httpd.apache.org/) 1.3+, [nginx](https://www.nginx.com/solutions/web-server/) 0.7+, [IIS](http://www.iis.net/) 5+ or [litespeed](https://www.litespeedtech.com/products/litespeed-web-server/overview) 4.0.2+. If there's a web server you feel we should be actively testing (e.g. [lighttpd](https://www.lighttpd.net/)), we're [interested in hearing](https://www.w3-edge.com/contact/).

= Is this plugin server cluster and load balancer friendly? =

Yes, built from the ground up with scale and current hosting paradigms in mind.

= What is the purpose of the "Media Library Import" tool and how do I use it? =

The media library import tool is for old or "messy" WordPress installations that have attachments (images etc in posts or pages) scattered about the web server or "hot linked" to 3rd party sites instead of properly using the media library.

The tool will scan your posts and pages for the cases above and copy them to your media library, update your posts to use the link addresses and produce a .htaccess file containing the list of of permanent redirects, so search engines can find the files in their new location.

You should backup your database before performing this operation.

= How do I find the JS and CSS to optimize (minify) them with this plugin? =

Use the "Help" button available on the Minify settings tab. Once open, the tool will look for and populate the CSS and JS files used in each template of the site for the active theme. To then add a file to the minify settings, click the checkbox next to that file. The embed location of JS files can also be specified to improve page render performance. Minify settings for all installed themes can be managed from the tool as well by selecting the theme from the drop down menu. Once done configuring minify settings, click the apply and close button, then save settings in the Minify settings tab.

= I don't understand what a CDN has to do with caching, that's completely different, no? =

Technically no, a CDN is a high performance cache that stores static assets (your theme files, media library etc) in various locations throughout the world in order to provide low latency access to them by readers in those regions. Use Total Cache to accelerate your site by putting your content closer to your users with our many CDN integrations including Cloudflare, StackPath, AWS and more.

= How do I use an Origin Pull (Mirror) CDN? =
Login to your CDN providers control panel or account management area. Following any set up steps they provide, create a new "pull zone" or "bucket" for your site's domain name. If there's a set up wizard or any troubleshooting tips your provider offers, be sure to review them. In the CDN tab of the plugin, enter the hostname your CDN provider provided in the "replace site's hostname with" field. You should always do a quick check by opening a test file from the CDN hostname, e.g. http://cdn.domain.com/favicon.ico. Troubleshoot with your CDN provider until this test is successful.

Now go to the General tab and click the checkbox and save the settings to enable CDN functionality and empty the cache for the changes to take effect.

= How do I configure Amazon Simple Storage Service (Amazon S3) or Amazon CloudFront as my CDN? =

First [create an S3 account](http://aws.amazon.com/) (unless using origin pull); it may take several hours for your account credentials to be functional. Next, you need to obtain your "Access key ID" and "Secret key" from the "Access Credentials" section of the "[Security Credentials](http://aws-portal.amazon.com/gp/aws/developer/account/index.html?action=access-key)" page of "My Account." Make sure the status is "active." Next, make sure that "Amazon Simple Storage Service (Amazon S3)" is the selected "CDN type" on the "General Settings" tab, then save the changes. Now on the "Content Delivery Network Settings" tab enter your "Access key," "Secret key" and enter a name (avoid special characters and spaces) for your bucket in the "Create a bucket" field by clicking the button of the same name. If using an existing bucket simply specify the bucket name in the "Bucket" field. Click the "Test S3 Upload" button and make sure that the test is successful, if not check your settings and try again. Save your settings.

Unless you wish to use CloudFront, you're almost done, skip to the next paragraph if you're using CloudFront. Go to the "General Settings" tab and click the "Enable" checkbox and save the settings to enable CDN functionality. Empty the cache for the changes to take effect. If preview mode is active you will need to "deploy" your changes for them to take effect.

To use CloudFront, perform all of the steps above, except select the "Amazon CloudFront" "CDN type" in the "Content Delivery Network" section of the "General Settings" tab. When creating a new bucket, the distribution ID will automatically be populated. Otherwise, proceed to the [AWS Management Console](https://console.aws.amazon.com/cloudfront/) and create a new distribution: select the S3 Bucket you created earlier as the "Origin," enter a [CNAME](http://docs.amazonwebservices.com/AmazonCloudFront/latest/DeveloperGuide/index.html?CNAMEs.html) if you wish to add one or more to your DNS Zone. Make sure that "Distribution Status" is enabled and "State" is deployed. Now on "Content Delivery Network" tab of the plugin, copy the subdomain found in the AWS Management Console and enter the CNAME used for the distribution in the "CNAME" field.

You may optionally, specify up to 10 hostnames to use rather than the default hostname, doing so will improve the render performance of your site's pages. Additional hostnames should also be specified in the settings for the distribution you're using in the AWS Management Console.

Now go to the General tab and click the "Enable" checkbox and save the settings to enable CDN functionality and empty the cache for the changes to take effect. If preview mode is active you will need to "deploy" your changes for them to take effect.

= How do I configure Rackspace Cloud Files as my CDN? =

First [create an account](http://www.rackspacecloud.com/cloud_hosting_products/files). Next, in the "Content Delivery Network" section of the "General Settings" tab, select Rackspace Cloud Files as the "CDN Type." Now, in the "Configuration" section of the "Content Delivery Network" tab, enter the "Username" and "API key" associated with your account (found in the API Access section of the [rackspace cloud control panel](https://manage.rackspacecloud.com/APIAccess.do)) in the respective fields. Next enter a name for the container to use (avoid special characters and spaces). If the operation is successful, the container's ID will automatically appear in the "Replace site's hostname with" field. You may optionally, specify the container name and container ID of an [existing container](https://manage.rackspacecloud.com/CloudFiles.do) if you wish. Click the "Test Cloud Files Upload" button and make sure that the test is successful, if not check your settings and try again. Save your settings. You're now ready to export your media library, theme and any other files to the CDN.

You may optionally, specify up to 10 hostnames to use rather than the default hostname, doing so will improve the render performance of your site's pages.

Now go to the General tab and click the "Enable" checkbox and save the settings to enable CDN functionality and empty the cache for the changes to take effect.  If preview mode is active you will need to "deploy" your changes for them to take effect.

= What is the purpose of the "modify attachment URLs" button? =

If the domain name of your site has changed, this tool is useful in updating your posts and pages to use the current addresses. For example, if your site used to be www.domain.com, and you decided to change it to domain.com, the result would either be many "broken" images or many unnecessary redirects (which slow down the visitor's browsing experience). You can use this tool to correct this and similar cases. Correcting the URLs of your images also allows the plugin to do a better job of determining which images are actually hosted with the CDN.

As always, it never hurts to back up your database first.

= Is this plugin comptatible with TDO Mini Forms? =

Captcha and recaptcha will work fine, however you will need to prevent any pages with forms from being cached. Add the page's URI to the "Never cache the following pages" box on the Page Cache Settings tab.

= Is this plugin comptatible with GD Star Rating? =

Yes. Follow these steps:

1. Enable dynamic loading of ratings by checking GD Star Rating -> Settings -> Features "Cache support option"
1. If Database cache enabled in W3 Total Cache add `wp_gdsr` to "Ignored query stems" field in the Database Cache settings tab, otherwise ratings will not updated after voting
1. Empty all caches

= I see garbage characters instead of the normal web site, what's going on here? =

If a theme or it's files use the call `php_flush()` or function `flush()` that will interfere with the plugins normal operation; making the plugin send cached files before essential operations have finished. The `flush()` call is no longer necessary and should be removed.

= How do I cache only the home page? =

Add `/.+` to page cache "Never cache the following pages" option on the page cache settings tab.

= I'm getting blank pages or 500 error codes when trying to upgrade on WordPress in network mode =

First, make sure the plugin is not active (disabled) network-wide. Then make sure it's deactivated network-wide. Now you should be able to successful upgrade without breaking your site.

= A notification about file owner appears along with an FTP form, how can I resolve this? =

The plugin uses WordPress FileSystem functionality to write to files. It checks if the file owner, file owner group of created files match process owner. If this is not the case it cannot write or modify files.

Typically, you should tell your web host about the permission issue and they should be able to resolve it.

You can however try adding <em>define('FS_METHOD', 'direct');</em> to wp-config.php to circumvent the file and folder checks.

= Does the Image Service extension use a lot of resources to convert images to WebP? =

No.  The Image Service extension converts common image file formats to the modern WebP format using our API services.  The conversions occur on our API service, so that resource usage does not impact your website server.

= Is image data retained by the Total Cache Image Service API? =

Image data received by our API is destroyed after a converted image is generated.  The converted iamges are destroyed once picked-up/downloaded to your website by the Total Cache plugin.

= This is too good to be true, how can I test the results? =

You will be able to see the results instantly on each page load, but for tangible metrics, you should consider using the following tools:

* [Google PageSpeed](https://developers.google.com/speed/pagespeed/)
* [Google Search Console Core Web Vitals Report](https://search.google.com/search-console/core-web-vitals/)
* [WebPagetest](https://www.webpagetest.org/test)
* [Pingdom](https://tools.pingdom.com/)
* [GTmetrix](https://gtmetrix.com/)

= I don't have time to deal with this, but I know I need it. Will you help me? =

Yes! Please [reach out to us](https://www.w3-edge.com/contact/) and we'll get you acclimated so you can "set it and forget it."

Install the plugin to read the full FAQ on the plugins FAQ tab.

== Installation ==

1. Deactivate and uninstall any other caching plugin you may be using. Pay special attention if you have customized the rewrite rules for fancy permalinks, have previously installed a caching plugin or have any browser caching rules as W3TC will automate management of all best practices. Also make sure wp-content/ and wp-content/uploads/ (temporarily) have 777 permissions before proceeding, e.g. in the terminal: `# chmod 777 /var/www/vhosts/domain.com/httpdocs/wp-content/` using your web hosting control panel or your FTP / SSH account.
1. Login as an administrator to your WordPress Admin account. Using the "Add New" menu option under the "Plugins" section of the navigation, you can either search for: w3 total cache or if you've downloaded the plugin already, click the "Upload" link, find the .zip file you download and then click "Install Now". Or you can unzip and FTP upload the plugin to your plugins directory (wp-content/plugins/). In either case, when done wp-content/plugins/w3-total-cache/ should exist.
1. Locate and activate the plugin on the "Plugins" page. Page caching will **automatically be running** in basic mode. Set the permissions of wp-content and wp-content/uploads back to 755, e.g. in the terminal: `# chmod 755 /var/www/vhosts/domain.com/httpdocs/wp-content/`.
1. Now click the "Settings" link to proceed to the "General Settings" tab; in most cases, "disk enhanced" mode for page cache is a "good" starting point.
1. The "Compatibility mode" option found in the advanced section of the "Page Cache Settings" tab will enable functionality that optimizes the interoperablity of caching with WordPress, is disabled by default, but highly recommended. Years of testing in hundreds of thousands of installations have helped us learn how to make caching behave well with WordPress. The tradeoff is that disk enhanced page cache performance under load tests will be decreased by ~20% at scale.
1. *Recommended:* On the "Minify Settings" tab, all of the recommended settings are preset. If auto mode causes issues with your web site's layout, switch to manual mode and use the help button to simplify discovery of your CSS and JS files and groups. Pay close attention to the method and location of your JS group embeddings. See the plugin's FAQ for more information on usage.
1. *Recommended:* On the "Browser Cache" tab, HTTP compression is enabled by default. Make sure to enable other options to suit your goals.
1. *Recommended:* If you already have a content delivery network (CDN) provider, proceed to the "Content Delivery Network" tab and populate the fields and set your preferences. If you do not use the Media Library, you will need to import your images etc into the default locations. Use the Media Library Import Tool on the "Content Delivery Network" tab to perform this task. If you do not have a CDN provider, you can still improve your site's performance using the "Self-hosted" method. On your own server, create a subdomain and matching DNS Zone record; e.g. static.domain.com and configure FTP options on the "Content Delivery Network" tab accordingly. Be sure to FTP upload the appropriate files, using the available upload buttons.
1. *Optional:* On the "Database Cache" tab, the recommended settings are preset. If using a shared hosting account use the "disk" method with caution, the response time of the disk may not be fast enough, so this option is disabled by default. Try object caching instead for shared hosting.
1. *Optional:* On the "Object Cache" tab, all of the recommended settings are preset. If using a shared hosting account use the "disk" method with caution, the response time of the disk may not be fast enough, so this option is disabled by default. Test this option with and without database cache to ensure that it provides a performance increase.
1. *Optional:* On the "User Agent Groups" tab, specify any user agents, like mobile phones if a mobile theme is used.

== What users have to say: ==

* Read [testimonials](https://twitter.com/w3edge/favorites) from W3TC users.

== Who do I thank for all of this? ==

It's quite difficult to recall all of the innovators that have shared their thoughts, code and experiences in the blogosphere over the years, but here are some names to get you started:

* [Steve Souders](http://stevesouders.com/)
* [Steve Clay](http://mrclay.org/)
* [Ryan Grove](http://wonko.com/)
* [Nicholas Zakas](http://www.nczonline.net/blog/2009/06/23/loading-javascript-without-blocking/)
* [Ryan Dean](http://rtdean.livejournal.com/)
* [Andrei Zmievski](http://gravitonic.com/)
* George Schlossnagle
* Daniel Cowgill
* [Rasmus Lerdorf](http://toys.lerdorf.com/)
* [Gopal Vijayaraghavan](http://notmysock.org/)
* [Bart Vanbraban](http://eaccelerator.net/)
* [mOo](http://xcache.lighttpd.net/)

Please reach out to all of these people and support their projects if you're so inclined.

== Changelog ==

= 2.3.1 =
* Fix: PHP 8 compatibility: Invalid return type if Browser Cache is disabled
* Fix: Added AWS SNS message classes (aws/aws-php-sns-message-validator)
* Fix: PageSpeed service: messages and escaping
* Fix: Image Service meta query handling
* Update: Dependency version updates
* Update: Content-Security-Policy (CSP) and Content-Security-Policy-Report-Only (CSPRO) header field configuration

= 2.3.0 =
* Feature: PageSpeed Insights reports and performance page widget
* Feature: Added basic OpenLiteSpeed support
* Feature: Add Permissions-Policy to mirror Feature-Policy directives
* Fix: PHP 8.2 compatibility
* Fix: GuzzleHttp 7 conflict with Azure
* Fix: Allow object cache updates when using WP-CLI
* Fix: Added missing Page Cache configuration "host" value
* Fix: Missing on_comment_status action callback
* Fix: Flush cache on attachment update
* Fix: Varnish flush for posts
* Update: Improved comment status logic for flushing database and object caches
* Update: Adjusted FTP form style
* Update: Removed deprecated MaxCDN and NetDNA components and added a notice if one was used
* Update: Removed deprecated FeedBurner

= 2.2.12 =
* Fix: Comment status change error
* Fix: Varnish flush post arguments

= 2.2.11 =
* Fix: Error when flushing page cache after an attachment update

= 2.2.10 =
* Fix: Optimized and fixed object cache flushing
* Fix: Scheduled post page cache flushing
* Fix: Admin bar flush cache for current page with disabled purge policy
* Fix: Loop when disabling Minify HTTP/2 push setting
* Fix: Extension admin notice missing links
* Update: Removed custom translation files

= 2.2.9 =
* Fix: Reset our textdomain for translations

= 2.2.8 =
* Fix: Escape output in compatibility checker, minify, and New Relic pages
* Fix: Admin notice buttons on non-plugin pages
* Fix: Namespace on exception type in a minify class
* Fix: Translation issues due to hooks and typos
* Fix: Broken JavaScript in admin_print_scripts calls when language is not English
* Fix: Deprecated warnings in JS and CSS minify
* Update: Translation files

= 2.2.7 =
* Fix: Updated database cache connection class to avoid deprecated warnings in WordPress 6.1
* Fix: Redis: Fixed handling of retry interval and timeout options for usage statistics
* Enhancement: Redis: Added TLS/SSL certificate verification option
* Enhancement: Page cache: Added query string exemptions

= 2.2.6 =
* Fix: Error clearing all cache when using Cloudfront full CDN in Pro

= 2.2.5 =
* Fix: Revert WooCommerce Variation Image Gallery plugin CDN filter
* Fix: DB cache syntax error in PHP 5.6
* Fix: Added missing space to S3 CDN bucket label
* Fix: JS error for CloudFront CDN related check on non-W3TC pages
* Fix: Page cache unpack warning for empty/malformed files
* Enhancement: Image Service pre_get_posts anonymous action now hooked (w3tc_modify_query_obj)
* Enhancement: Image Service ajax_query_attachments_args anonymous action now hooked (w3tc_filter_ajax_args)

= 2.2.4 =
* Fix: Extensions URL in settings
* Fix: Redis undefined array key warnings
* Fix: Redis connect issue based on phpredis version
* Fix: Sanitization of licensing messages
* Fix: DB cache error in Ajax
* Fix: Call to undefined function in DB cache query class
* Fix: PHP 8 compatibility: join
* Fix: WooCommerce Variation Image Gallery plugin CDN filter
* Enhancement: Add setting for AWS S3 public objects in ACL
* Enhancement: Check if post is empty before cache flush
* Enhancement: Add max lifetime setting for non-disk page cache
* Enhancement: Add notice when selecting CDN using CloudFront
* Update: CSS Tidy 1.7.3 => 2.0.1
* Update: Add sns-message-validator
* Security: Ensure cache writes in cache folders

= 2.2.3 =
* Fix: Redis Cache: Removed exception on warnings
* Fix: Compatibility check for WP_CACHE
* Fix: Flush all cache cache except Cloudflare button
* Fix: License terms update notice escaping
* Fix: Feature Showcase: Image Service activate button
* Security: Updated guzzlehttp/guzzle to 6.5.8

= 2.2.2 =
* Security: PHPCS and WPCS updates
* Security: Updated guzzlehttp/guzzle to 6.5.6
* Security: Updated guzzlehttp/psr7 to 1.8.5
* Fix: Cloudflare flush all cache
* Fix: Access log test
* Fix: Better handling for PHP 5.6
* Fix: Convert Redis warnings to exceptions
* Fix: WordPress 5.5 image lazy loading
* Fix: Infinite loop when using database cluster configuration
* Fix: Database cluster logic
* Fix: FTP credentials form
* Fix: Preview deploy button
* Fix: Image Service links in multisite network admin
* Fix: Enable Image Service settings changes in multisite blog/sub sites
* Enhancement: Updated Cloudflare settings to allow a global API key or token
* Enhancement: Added Cloudflare CDN public objects option to settings
* Enhancement: Added timeout settings for Redis
* Enhancement: Added TLS/SSL certificate verification option for Redis
* Enhancement: Added Image Service visibility option
* Enhancement: Updated Image Service limit notification
* Enhancement: Better handling of trailing slash URLs
* Update: Adjusted lightbox for accessibility
* Update: Removed deprecated opcache flush

= 2.2.1 =
* Fix: Cloudflare: Removed use of the retired ip_lkup V1 endpoint
* Fix: Prevent error in some environments using non-direct filesystems
* Fix: Added better checking for some filesystem actions
* Fix: AWS CloudFront: Reverted async change for cache invalidation to honor promises
* Enhancement: Added option to exclude minified JS files from being processed by Rocket Loader
* Enhancement: Improved handling of Image Service rate-limiting and error messages

= 2.2.0 =
* Feature: Image Service API extension: WebP conversion options

= 2.1.9 =
* Fix: Cloudflare Dashboard Widget: Updated to use GraphQL
* Fix: Cloudflare Dashboard Widget: Use WordPress timezone
* Fix: CDN: Execute purge only if hosting is enabled, to prevent unneeded delays
* Fix: Published/modified custom posts not clearing the archive cache(s)
* Fix: Native WordPress sitemap caching
* Fix: Extra MIME groups other than controlled by settings were added to rules
* Fix: Usage Statistics: Not functioning when object cache is set to Redis
* Fix: AMP Extension: Prevent popup admin bar for endpoints
* Fix: Setup Guide Wizard: CSS for long translations
* Fix: Opcache Settings: Validate timestamp indicator checkbox
* Update: Remove robots.txt cache toggle setting
* Enhancement: Impove 404 detection
* Enhancement: Improved compatibility check indicators
* Enhancement: AWS CloudFront: Faster cache invalidation using async

= 2.1.8 =
* Fix: Corrected handling of robots.txt (file and filter)

= 2.1.7 =
* Fix: Corrected relative paths used in the JS minify YUI Compressor
* Fix: Disallow crawling of cache directory
* Fix: Responsive display for the dashboard
* Enhancement: Added lazy load threshold setting
* Enhancement: Added feature policy security headers to settings

= 2.1.6 =
* Fix: JS minify issue with template literal backticks
* Fix: Do not redirect when using WP-CLI
* Fix: Missing whitespace in Memcached Nginx configuration
* Fix: Setting for CDN over passive FTP
* Fix: Updated CDN Minify regex
* Fix: Added missing text domains and fixed translations
* Enhancement: Allow default AWS credentials provider
* Enhancement: Added error logging when minification base URL is not found

= 2.1.5 =
* Fix: Sanitize extension argument

= 2.1.4 =
* Fix: Use Memcached server from config for Nginx rules instead of localhost
* Fix: Allow more characters in CDN hostname sanitization
* Fix: Added missing textdomains for Browser Cache settings
* Fix: Avoid a possible PHP warning in LazyLoad mutator
* Enhancement: Added a filter w3tc_cdn_cf_flush_all_uris for CloudFront purging

= 2.1.3 =
* Fix: Authenticated Persistent XSS & XFS in CDN admin page
* Update: AWS library version 3.183.0
* Update: Minify: Include theme template files using page_* filenames

= 2.1.2 =
* Fix: Skip removing spaces around "<li>" tags in HTML Minify
* Fix: Updated admin URL logic for multisite installations
* Fix: TransparentCDN purge URL validation
* Fix: Added an option to use ABSPATH as the document root for Minify
* Fix: Database cache debug message
* Update: Added regions for AWS S3 (af-south-1, cn-north-1, cn-northwest-1, eu-south-1)
* Update: Added MIME types AVIF and AVIFS for Browser Cache rules
* Update: Enhanced "get_pagenum_link" filter
* Update: Removed "comment" from the non-persistent object cache group

= 2.1.1 =
* Fix: Move Minify library to a namespace to avoid conflicts with other plugins
* Fix: Check for AWS before loading functions
* Fix: Update Minify ClosureCompiler base URL; use HTTPS
* Fix: Corrected getting the network siteurl
* Fix: Prevent PHP warning in CurlFactory
* Update: Added information links to general minify options
* Update: Added video/ogg support for browser caching

= 2.1.0 =
* Feature: Added a Feature Showcase to highlight new and existing features
* Update: Consolidated cache groups settings pages
* Update: Replaced deprecated jQuery method for WordPress 5.6
* Fix: PHP warnings for sprintf placeholders in PHP 8
* Fix: PHP deprecated warnings in PHP 8
* Fix: Browser Cache Quick Reference Chart link
* Fix: Bad nonce in help
* Fix: Google Drive CDN JavaScript

= 2.0.1 =
* Fix: Corrected redirection logic for the new Setup Guide
* Fix: Fixed JavaScript w3tc_ga error

= 2.0.0 =
* Feature: Added the Setup Guide wizard for onboarding
* Update: Updated jQuery compatibility and methods deprecated in WordPress 5.6
* Fix: Browser Cache: Fixed ExpiresByType code; changed from modified time to client access time

= 0.15.2 =
* Fix: Minify: Do not remove quotes around meta tags
* Fix: Minify: Removal of spaces in calc function was breaking CSS
* Fix: Browser Cache: Query string was not added to prevent caching after setting changes
* Fix: Avoid warning when sending an empty URL for purging
* Update: Added a filter for minified JavaScript content
* Update: Minify: Added options for minify only got both JS and CSS in auto mode

= 0.15.1 =
* Fix: Fixed Memcached flush logic
* Fix: Remove disk enhanced rewrites when disabling page cache
* Fix: Better handle conflicts on activation

= 0.15.0 =
* Feature: Added TransparentCDN full-site delivery option
* Fix: Update settings on activation in a changed environment
* Fix: Fixed a compatibility check for Apache when PHP is running as CGI
* Fix: Always set HSTS headers in Apache; not only for 2xx HTTP codes
* Fix: Implemented anatomic incrementing of key version in Memcache(d)
* Update: Allow filtering of w3tc_minify_url_for_files Minify URL for files

= 0.14.4 =
* Fix: Cleanup widget and postbox display for WordPress 5.5
* Fix: Update to PageSpeed API v5, show webvitals metrics
* Fix: Console error when adminbar is hidden and PageSpeed module is active
* Fix: Stats view JS issue
* Fix: Deprecated jQuery warnings
* Fix: Require files for request_filesystem_credentials() call
* Added option to disable jquery-migrate on the front-end. Fixed #172 master (#240)

= 0.14.3 =
* Fix: Take "Accepted Query Strings" into account when "Cache query strings" enabled
* Fixed typo in variable for lazy loading
* Update: Add lazy load Google Maps reference to the general settings page
* Update: Support background-image: together with background: for lazy loading

= 0.14.2 =
* Fixed WP-CLI redirect issue in multisite
* Fix: Avoid PREG_JIT_STACKLIMIT_ERROR in minify
* Fix: Prevent empty needle PHP warning
* Update: Allow to specify URIs with a query string in Additional Pages

= 0.14.1 =
* Fixed CSS minify URL rewrite logic that affected some lazy loading and CSS URL addresses using protocols

= 0.14.0 =
* Added lazy loading for Google Maps
* Added a filter w3tc_minify_css_content for minified contents
* Fixed a minify regex issue in non-Unicode websites
* Fixed a PHP notice in WPMU: accessing array offset on null
* Fixed a minify issue where embedded CSS URL fragments were converted incorrectly
* i18n improvement
* Changed default to disabled for wp-admin requests in the object cache

= 0.13.3 =
* Fixed HTML minification of img elements containing embedded SVG strings
* Removed an identifying value for GDPR

= 0.13.2 =
* Fix: Dont store content of HEAD requests
* Updated informational URL on page cache static page comments

= 0.13.1 =
* Fixed php warnings in PgCache_ContentGrabber.php

= 0.13.0 =
* Added new Pro feature, Debug - Purge Stack Trace
* Added "Feature Policy" security header
* Removed deprecated get_magic_quotes_gpc()
* Improved AMP Extension by ignoring value of amp querystring marker in request if passed without value in config
* Improved lazyload by not processing elements with skip-lazy class or data-skip-lazy attribute
* Fixed caching of query-string normalization redirects, no longer cached when cache key is normalized by accept querystring arguments, caused redirect loop

= 0.12.0 =
* Added querystring based URL structures for AMP pages
* Added filter of minify options
* Added lazyload picture tag support
* Removed footer link "Support Us" option
* Improved wp_die handling
* Improved lazyload handling of content in script tags
* Improved lazyload handling of feeds
* Improved printing tags coming from feeds
* Improved handling of modified posts before wp_rewrite initialized
* Nginx rules changed a lot to avoid "location" block conflicts. That change may cause problems on some systems using non-default WordPress rules - keep a backup of your original rules
* Improved handling of .htaccess files in regard to EOF
* Fixed Varnish purging
* Fixed html minification of data tags equaling 0

= 0.11.0 =
* Added recommendation for BoldGrid's Total Upkeep plugin
* Added new lazy loading feature
* Removed New Relic extension by default for new installations
* Updated usage of html minification and quote removal
* Improved memcached config and added optional binary protocol setting
* Improved process of renewing expired licenses
* Improved page cache purging
* Improved FAQ link by opening in new window
* Improved detection of detect_post_id
* Improved REST caching in relation to cache headers like X-WP-*
* Improved Vary User-Agent header usage
* Improved various features with AMP pages and HTTP2
* Improved redis connection string to allow for tls://host:port format
* Fixed file headers for Cloudfront S3 CDN
* Fixed fatal error on with flush / SNS
* Fixed comments with URLs within minify debug mode
* Fixed ObjectCache statistics within footer
* Fixed temporary hotfix with wp_die and regular output
* Fixed fragment cache header link
* Fixed flushing of /feed and /feed/ cache
* Fixed js error in widget
* Fixed fatal cache flush error caused by empty $wp_rewrite
* Fixed path for file_generic REST caching on non-default port
* Fixed test minify button with Closure Compiler engine

= 0.10.2 =
* Fixed compatibility with wpdb::prepare in WordPress 5.3

= 0.10.1 =
* Fixed slowdown in memcached engine
* Fixed Purge Cache menu links so they flush current blog in WPMU
* Fixed error during upgrade, "Call to undefined method W3TC\Util_Content::is_database_error"
* Updated Redis cache engine to avoid "Function Redis::delete() is deprecated" warning

= 0.10.0 =
* Improved Statistics component for pro users
* Improved support for CloudFront distributions with multiple origins
* Improved redirects by using safter wp_safe redirect
* Improved .htaccess usage when pagecache does not require it
* Improved protection of unexpected values in global variables
* Added more Amazon S3 regions
* Added support for memcached binary protocol when available
* Added caching for webp MIME type
* Updated S3 bucket creation by settings CORS policy
* Updated blogmap to allow urls with custom ports
* Fixed usage of base url with minify
* Fixed mixing content of sync & async scripts with minify

* Fixed S3 + CloudFront urls when CNAMEs not used

= 0.9.7.5 =
* Updated AWS library
* Added support of set_sql_mode by dbcluster
* Improved support for webserver running on non-default port with disk-enhanced
* Improved menu icons
* Fixed php warning when remote service cannot be loaded
* Fixed php warnings on support page

= 0.9.7.4 =
* Fixed PHP warning when Redis integration not configured correctly
* Fixed 404 in multisite caused by subdirectory issue
* Fixed object cache issue in multisite where object cache was cleared at wrong time
* Fixed database cluster in WordPress 5.1
* Fixed warning caused by user agent theme change used
* Fixed minification in multisite when URLs were set to root-blog based url
* Fixed undefined w3tc_ga issue
* Improved purging of current page by using post_id instead of URL
* Improved cache delivery of /feed URLs
* Improved security on calls to opcache flush
* Improved minification of files in environments running on non-default ports

= 0.9.7.3 =
* Fixed caching of redirect responses based on empty response body
* Improved compatibility with WordPress 5.1
* Improved transports, unix: prefix not required
* Improved minify html

= 0.9.7.2 =
* Fixed fatal error during media file upload with CDN module active
* Fixed removal of empty values, JSON encoded string in attribute, trailing quote at end of tag, and the handling of anchors in HTML minify
* Fixed undefined index warning
* Fixed fatal error when purging CDN using full site delivery

= 0.9.7.1 =
* Fixed undefined variable notice
* Fixed "No such file or directory" warning
* Fixed writing to PHP error log rather than WordPress debug log
* Fixed default referrer policy should be "no-referrer-when-downgrade"
* Fixed php_flag error related to browser cache, using ini_set instead
* Fixed CloudFlare IPv6 check undefined offset
* Fixed Undefined constant WP_ROOT
* Fixed frame-ancestors being overwritten by frame-src
* Fixed missing semicolon in nginx configuration
* Fixed HTTP/2 URLs handling for browser cache and CDN modules
* Fixed display of CDN debug information
* Fixed CSS Minification with Google Fonts when included via "Include external files/libraries" and non-latin character-sets are loaded
* Fixed media query string not updating when all caches were purged
* Fixed double slash with ABSPATH if file exists
* Fixed setting max-age and expires header simultaneously
* Fixed SASL detection for PECL Memcached
* Fixed handling of manually entered objects to be purged on CDN
* Fixed query string handling in Nginx
* Improved error handling with Cloudfront
* Improved page cache logging
* Improved multi-tenant support for memory-based caching engines
* Improved CSS minification
* Improved purge behavior for changed media objects when using CDN
* Improved compatibility with sitemap plugins
* Added support for Memcached for Nginx
* Added support for caching webm files
* Added Brotli HTTP compression support
* Added StackPath full site delivery support
* Added _wc_session_ to the list of ignored query stems for improved WooCommerce compatibility

= 0.9.7 =
* Fixed minified files not being hosted by CDN when enabled if "host minified files" is disabled
* Fixed warning thrown when purge all was selected (via nigrosimone)
* Fixed undefined offset error in fragment cache
* Fixed MaxCDN test button failure when debug mode is enabled
* Fixed purging of feeds when cache feeds option is enabeld
* Improved handling of errors when full site delivery isn't set
* Improved nginx.conf to support xml caching
* Improved nginx.conf to support HSTS for static files
* Improved minify's handling of query strings
* Improved database caching, frequent wp_options no longer flush posts or comments data
* Improved Limelight Networks CDN integration
* Improved FAQ, they're now hosted in the GitHub public repository
* Improved handling for /*<![CDATA[*/ in HTML minify engine
* Imporved garbage collection for basic disk caching
* Improved HSTS support (via Dave Welsh)
* Improved reliabilty of CSS embed options
* Improved New Relic requirements in compatibility test
* Added StackPath CDN integration (including full site delivery)
* Added support for page cache priming via WP-CLI via prime function
* Added filter support for managing cache groups
* Added API for flushing individual cache groups via flush_group function
* Added purge support for JSON cache e.g. cached REST API requests
* Added filter support for managing database cache settings
* Added filter support before (w3tc_process_content) and after (w3tc_processed_content) a cache object is created
* Added compatibility for AMPforWP plugin
* Added JSON caching support for Pro subscribers
* Added additional security headers (via amiga-500)

= 0.9.6 =
* Fixed anonymous usage tracking, default to disabled
* Fixed incorrect minify cache data written if target directory missing
* Fixed empty minify cache file written when file locking enabled
* Fixed missing commas in CSS (via nigrosimone)
* Fixed typo in object cache engine (via Furniel)
* Fixed incorrect reuse of redis connections when persistent connections option enabled
* Fixed reliability of Google Drive (via jikamens)
* Fixed handling of UTF-8 encoded files by writing them in binary (via jikamens)
* Improved Full Site Delivery configuration user flow on the General and CDN settings screens
* Improved content type matching and cache hits as a result
* Improved minify file locking logic
* Improved visual langage of the compatibility test (via Furniel)
* Improved configuration file management
* Improved MaxCDN set up wizard
* Improved page cache's accepted query string handling to handle optional values and add support for disk enhanced mode (via amiga-500, nigrosimone)
* Improved handling of timeouts to origin push CDN proviers
* Added HTTP/2 push headers for disk enhanced page caching (via nigrosimone)
* Added X-Forwarded-Proto header for use cases like HTTPS recognition behind proxies or load balancers
* Added multiple CDN support i.e. static file objects and pages, posts, feeds, API responses etc to use different respective CDN providers
* Added page caching by cookie name or value (sponsored by SQweb)
* Added toggle for CORS header to improve inter-operatbility with various CDN providers
* Added support for CDN hosted media to media library (inspired by amiga-500)
* Added object caching of AJAX calls (via andyexeter)
* Enterprise features are now available to Pro subscribers! Including reading from multiple databases concurrently and purging caches across multiple hosts via a Message Bus


= 0.9.5.4 =
* Fixed regression with browser caching and query strings

= 0.9.5.3 =
* Fixed handling of HTTP compressed documents in PHP v5.3 (via amiga-500)
* Fixed a bug with accelerated mobile pages (via nigrosimone)
* Improved reliability of minify in manual mode
* Improved JavaScript interoperability with CDATA use cases
* Improved file name generation on Windows for IIS servers
* Improved handling of # in URLs
* Improved handling of exclusions for e-commerce in Genesis Framework
* Improved handling of headers for Microsoft Azure
* Improved functionality with existing Cloudfront Distributions when configuring Full Site Delivery
* Improved minify debug logging
* Improved handling of URLs that omit the protocol
* Improved handling of custom files with CDN (via amiga-500)
* Updated CSSTidy library (via nigrosimone and amiga-500)
* Added Swarmify Video Optimization Extension [Hat tip the Swarmify Team]
* Added flushing of AMP pages

= 0.9.5.2 =
* Fixed security issue by protecting configuration data by adding .php to relevant files
* Fixed security issue with the creation of dot folders that could be abused
* Fixed handling HTTP compression for uncached pages
* Fixed handling of .svgz files
* Added expiration headers to webP images
* Added support for Microsoft Azure’s latest API
* Added ability to cache WP Admin. Recommended setting, is off. (Improved WP Admin performance with object caching enabled)
* Added HTTP/2 Push support for minified files
* Added option management support for wp-cli
* Improved handling of uncompressed minified files
* Improved handling of purging of modified pages / posts
* Improved compatibility with Rackspace Cloud Files
* Improved initial CDN configuration reliability
* Improved reliability of object caching
* Improved PHP 7.0 compatibility
* Improved PHP 4.3 compatibility
* Improved HTTP/2 support
* Improved CSS embed handling
* Improved reliability of object cache, transients now fallback to database
* Improved handling of cached http compressed objects

= 0.9.5.1 =
* Fixed missing namespace, which caused issues with other implementations of Google APIs
* Fixed handling Cloudflare zone list being incomplete for users with many zones
* Added extension to support Accelerated Mobile Pages (AMP)
* Added notification for users that are still using PHP 5.2 (end of life in 2011)
* Improved default settings
* Improved compatibility with Yoast SEO sitemap caching
* Improved compatability with Jetpack
* Improved directory handling on IIS
* Improved backwards compatibility for 3rd party implementations against legacy W3TC functions

= 0.9.5 =
* Fixed XSS vulnerability
* Fixed issues with dismissing overlays
* Fixed handling of tilde in URLs
* Fixed issue with HTTP compression header when using mfunc calls
* Fixed cache ID issue with minify in network mode
* Fixed rare issue of caching empty document when some PHP errors occur in themes or plugins
* Fixed caching of query strings
* Added support for APCu Opcode Cache
* Added support for Redis
* Added support for Google Drive
* Added support for Amazon S3-compatible stroage services
* Added support for PECL memcached
* Added support for srcset elements
* Added support for Rackspace CDN Origin Pull
* Added support for minification of external fonts
* Added support for WOFF2 font format
* Added support for FTPS (FTP-SSL, S-FTP)
* Added YUI Compressor's PHP Port of the CSS minifier
* Added Narcissus' JS minifier
* Added purge of parent page when attachments are added or updated
* Added Highwinds CDN provider
* Added "Validate Timestamps" option for compatible opcode caches functions like apc.stat are enabled
* Added Full Site Delivery for Pro subscribers
* Added HTTP Strict Transport Security (HSTS) support
* Added a sample extension for developers to reference
* Added Rackspace Cloud Files Multi-Region Support
* Added more support for exclusions to database cache
* Added more optionality to minifiers
* Added WPML Performance Extension
* Added use of [namespace](http://php.net/manual/en/language.namespaces.rationale.php) which creates mininum dependency on version PHP 5.3
* Improved PHP 5.6 compatibility
* Improved PHP 7 compatibility
* Improved performance menu in admin bar, including purging of specific cache engines and more
* Improved SSL interoperability
* Improved reliablity of test buttons
* Improved nomenclature of caching files for higher cache hit rates
* Improved nginx compatibility
* Improved WP CLI support
* Improved Cloudflare compatibility (now using latest APIs), Cloudflare must be re-authorized
* Improved AWS API compatibility (now using latest APIs)
* Improved Rackspace Cloud Files compatibility (now using latest APIs)
* Improved page cache purge for extensions like cloudflare and other reverse proxy use cases
* Improved extension framework functionality
* Improved compatibility of headers like ETag and content encoding
* Improved template fragment caching
* Improved notifications, warnings and errors
* Improved moble user agents detection
* Improved security with nonces and form elements
* Improved security throughout the codebase
* Improved detail of debug messages
* Improved Amazon SNS security (validation)
* Improved minify's ability to match script tags without type attribute

= 0.9.4 =
* Fixed undefined w3tc_button_link
* Fixed support and other form submissions
* Fixed extension enabled key error
* Fixed Test CDN errors
* Fixed trailing slashes in custom wp content path and Minify
* Fixed WP_PLUGIN_DIR not being available when object-cache.php is loaded and W3TC constant not set
* Fixed Minify Auto and restructuring of JS code placement on page
* Fixed remove / replace drop in file on plugins page
* Fixed false positive check for legacy code
* Fixed deprecated wpdb escape
* Fixed Fragment Caching and APC anomalies
* Fixed cached configs causing 500 error on interrupted file writes
* Fixed readfile errors on servers with the functionality disabled
* Fixed false positives for license key verification
* Fixed debug information not printed on cached pages
* Fixed backwards compatibility and flushing and added doing it wrong notification
* Fixed "Prevent caching of objects after settings change"
* Fixed "Use late init" being shown as enabled with Disc:Enhanced
* Fixed missing param in APC cache method declaration
* Fixed user roles property not begin an array
* Fixed adding empty Vary header
* Fixed notice on failed upgrade licencing check
* Fixed Database Cache description text
* Fixed duplicate bb10 agents
* Fixed settings link in Minify Auto notification
* Fixed notice with undefined constant
* Fixed nginx configuration and Referrer, User Groups setting
* Fixed Genesis settings and Suhosin field name limit error
* Fixed Genesis and Fragment Caching (caching categories etc)
* Fixed CDN being enabled when creating NetDNA / MaxCDN pull zone
* Fixed NewRelic related notice in compatibility popup
* Fixed trailing slash issue in filename to url conversion
* Fixed issue with wp in subdirectory and relative minimal manual urls
* Fixed issue with widget styling
* Fixed issue with Purge All button action
* Fixed issue with exporting of settings
* Fixed issue with plugin interferring with preview theme
* Fixed issue with malformed config files
* Added caching of list of posts pages (tags, categories etc) to Genesis extension a long with flush it checkbox
* Added typecasting on expiration time in object cache drop-in
* Added capability check for save options
* Added FeedBurner extension
* Added woff support to Browser Cache
* Added new CloudFlare IPs
* Added support for WordPress defined charset and collate in CDN queue table creation
* Added WordPress SEO by Yoast extension
* Added *.less to CDN theme uploads and MIME
* Added default settings for MaxCDN Pull Zone creation
* Added call to change MaxCDN canonical header setting to match plugin setting
* Added one button default pull zone creation to MaxCDN without refresh
* Added MaxCDN authorization validation
* Added whitelist IPs notification for MaxCDN
* Added support for use of existing zones without refresh
* Added new mime types
* Added support for separate domains for frontend and admin backend
* Added CloudFlare as an extension
* Added nofollow to blogroll links
* Added DEV mode support to PRO version
* Added EDGE MODE functionality
* Improved wrapper functions in plugins.php for plugin / theme authors
* Improved reliability of NetDNA / MaxCDN API calls by using WP HTTP and not cURL
* Improved Fragment Caching debug information
* Improved preview mode, removed query string requirement
* Improved FAQ structure
* Improved empty minify/pgcache cache notification when using CDN
* Improved default settings for MaxCDN zone creation
* Improved CDN queue performance
* Improved blogmap url sanitation
* Improved MaxCDN automatic zone creation process
* Improved license key saving and Pro mode activation on Pro license purchases
* Updated EDGE MODE: Full site mirroring support for MaxCDN
* Updated translations


== Upgrade Notice ==

= 0.9.7.5 =
Users running Cloudflare CDN may experience issues beginning June 6th. Please upgrade to W3 Total Cache 0.9.7.5 for the latest Cloudflare patches.

= 0.9.5.3 =
Thanks for using W3 Total Cache! This release includes compatibility fixes that have been reported. In addition, numerous other improvements are now yours!

= 0.9.5.2 =
Thanks for using W3 Total Cache! This release includes security fixes that have been reported. In addition, numerous other improvements are now yours!

= 0.9.5.1 =
Thanks for using W3 Total Cache! This release includes security fixes that have been reported. In addition, numerous other improvements are now yours!

= 0.9.5 =
Thanks for using W3 Total Cache! This release includes fixes for recent XSS security issues that have been reported. In addition, hundreds of other improvements are now yours!

= 0.9.4 =
Thanks for using W3 Total Cache! This release introduces hundreds of well-tested stability fixes since the last release as well as a new mode called "edge mode," which allows us to make releases more often containing new features that are still undergoing testing or active iteration.

= 0.9.2.11 =
Thanks for using W3 Total Cache! This release includes various fixes for MaxCDN and minify users. As always there are general stability / compatibility improvements. Make sure to test in a sandbox or staging environment and report any issues via the bug submission form available on the support tab of the plugin.

= 0.9.2.10 =
Thanks for using W3 Total Cache! This release includes performance improvements for every type of caching and numerous bug fixes and stability / compatbility improvements. Make sure to keep W3TC updated to ensure optimal reliability and security.

= 0.9.2.9 =
Thanks for using W3 Total Cache! This release addresses security issues for Cloudflare users as well as users that implement fragment caching via the mfunc functionality. For those using mfunc, temporarily disable page caching to allow yourself time to check the FAQ tab for new usage instructions; if you have a staging environment, that is the most convenient way to test prior to production roll out.

= 0.9.2.8 =
Thanks for using W3 Total Cache! The recent releases attempted to use WordPress' built in support for managing files and folders and clearly has not worked. Since W3TC is a caching plugin, file management is a critical issue that will cause lots of issues if it doesn't work perfectly. This release is hopefully the last attempt to restore file management back to the reliability of previous versions (0.9.2.4 etc). We realize that having *any* problems is not acceptable, but caching means changing server behavior, so while this plugin is still in pre-release we're trying to focus on learning.
