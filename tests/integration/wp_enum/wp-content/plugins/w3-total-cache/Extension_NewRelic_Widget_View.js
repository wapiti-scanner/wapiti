jQuery(document).ready(function($) {
    function w3tcnr_load_basic() {
        $('.w3tcnr_loading').removeClass('w3tc_hidden');
        $('.w3tcnr_content').addClass('w3tc_hidden');
        $('.w3tcnr_error').addClass('w3tc_none');

        $.getJSON(ajaxurl + '?action=w3tc_ajax&_wpnonce=' + w3tc_nonce + 
            '&w3tc_action=newrelic_widgetdata_basic',
            function(data) {
                for (p in data) {
                    var v = data[p];
                    jQuery('.w3tcnr_' + p).html(v);
                }
                
                $('.w3tcnr_content').removeClass('w3tc_hidden');
                $('.w3tcnr_loading').addClass('w3tc_hidden');
            }
        ).fail(function() {
            $('.w3tcnr_error').removeClass('w3tc_none');
            $('.w3tcnr_content').addClass('w3tc_hidden');
            $('.w3tcnr_loading').addClass('w3tc_hidden');
        });
    }



    function w3tcnr_load_topfive(action, selector) {
        $.getJSON(ajaxurl + '?action=w3tc_ajax&_wpnonce=' + w3tc_nonce + 
            '&w3tc_action=' + action,
            function(data) {
                $(selector).html(data.content);

                // resize outer window to newly grown widget
                jQuery('#normal-sortables').masonry({
                    itemSelector: '.postbox'
                });
            }
        ).fail(function() {
            $(selector).html('<div class="w3tcnr_topfive_message">Request failed</div>');
        });
    }


    var nr_widget = jQuery('#new-relic-widget');
    nr_widget.find('div.top-five').hide();
    $('.w3tcnr-header-pageloads').click(function() {
        jQuery(this).find('div').toggleClass('close');
        jQuery(this).parents('.wrapper').find("div.top-five").toggle();

        w3tcnr_load_topfive('newrelic_widgetdata_pageloads', 
            '.w3tcnr_pageloads');
    });
    $('.w3tcnr-header-webtransactions').click(function() {
        jQuery(this).find('div').toggleClass('close');
        jQuery(this).parents('.wrapper').find("div.top-five").toggle();

        w3tcnr_load_topfive('newrelic_widgetdata_webtransactions', 
            '.w3tcnr_webtransactions');
    });
    $('.w3tcnr-header-dbtimes').click(function() {
        jQuery(this).find('div').toggleClass('close');
        jQuery(this).parents('.wrapper').find("div.top-five").toggle();

        w3tcnr_load_topfive('newrelic_widgetdata_dbtimes', 
            '.w3tcnr_dbtimes');
    });


    w3tcnr_load_basic();
});
