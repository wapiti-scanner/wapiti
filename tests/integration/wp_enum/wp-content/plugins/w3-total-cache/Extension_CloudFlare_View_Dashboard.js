jQuery(function() {
    jQuery('#w3tc_dashboard [type=submit]').bind('click', function(){
        jQuery(this).attr('was_clicked','yes');
    });

    jQuery('#w3tc_dashboard').submit(function(event) {
        var el = jQuery("[was_clicked=yes]").get(0);
        if (el.id == 'flush_all') {
            if (!confirm('Purging your site\'s CloudFlare cache will remove all CloudFlare cache files. It may take up to 48 hours for the CloudFlare cache to completely rebuild on CloudFlare\'s global network. Are you sure you want to purge CloudFlare the cache? Clicking cancel will cancel "empty all caches".')) {
                event.preventDefault();
            }
        }
        jQuery(el).removeAttr("was_clicked");
    });
});
