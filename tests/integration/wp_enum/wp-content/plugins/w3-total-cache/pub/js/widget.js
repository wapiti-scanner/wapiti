jQuery(function() {
    var ajaxurl = window.ajaxurl;

    jQuery(document).ready(function() {
        var forumLoading = jQuery('#w3tc_latest').find('div.inside:visible').find('.widget-loading');
        if (forumLoading.length) {
            var forumLoadingParent = forumLoading.parent();
            setTimeout(function() {
                forumLoadingParent.load(
                    ajaxurl + '?action=w3tc_widget_latest_ajax&_wpnonce=' +
                        jQuery(forumLoading).metadata().nonce,
                    function () {
                        forumLoadingParent.hide().slideDown('normal',
                            function() {
                                jQuery(this).css('display', '');
                            });
                    });
            }, 500);
        }
        var newsLoading = jQuery('#w3tc_latest_news').find('div.inside:visible').find('.widget-loading');
        if (newsLoading.length) {
            var newsLoadingParent = newsLoading.parent();
            setTimeout(function() {
                newsLoadingParent.load(
                    ajaxurl + '?action=w3tc_widget_latest_news_ajax&_wpnonce=' +
                        jQuery(newsLoading).metadata().nonce,
                    function () {
                        newsLoadingParent.hide().slideDown('normal',
                            function() {
                                jQuery(this).css('display', '');
                            });
                    });
            }, 500);
        }

        jQuery('.w3tc_generic_widgetservice_radio').click(function () {
            var o = jQuery(this);

            jQuery('#w3tc_generic_widgetservices_name').val(o.data('name'));
            jQuery('#w3tc_generic_widgetservices_value').val(o.data('value'));
            jQuery('#w3tc_generic_widgetservices_form_hash').val(o.data('form_hash'));
        });

		jQuery('#buy-w3-service-cancel').on('click', function () {
            jQuery('input:radio[name=service]:checked').prop('checked', false);
            jQuery('#buy-w3-service-area').empty();
            jQuery('#buy-w3-service').attr("disabled", "disabled");
        });
    });
});
