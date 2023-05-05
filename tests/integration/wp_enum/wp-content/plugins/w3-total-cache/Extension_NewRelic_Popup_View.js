jQuery(function($) {
    $('body')
        .on('click', '.w3tcnr_configure', function() {
            W3tc_Lightbox.open({
                id:'w3tc-overlay',
                close: '',
                width: 800,
                height: 400,
                url: ajaxurl + '?action=w3tc_ajax&_wpnonce=' + w3tc_nonce +
                    '&w3tc_action=newrelic_popup',
            });
        })



        .on('click', '.w3tcnr_list_applications', function() {
            var url = ajaxurl + '?action=w3tc_ajax&_wpnonce=' + w3tc_nonce +
                '&w3tc_action=newrelic_list_applications&api_key=' +
                encodeURIComponent($('.w3tcnr_api_key').val());
            W3tc_Lightbox.load(url);
        })



        .on('click', '.w3tcnr_apply_configuration', function() {
            var url = ajaxurl + '?action=w3tc_ajax&_wpnonce=' + w3tc_nonce +
                '&w3tc_action=newrelic_apply_configuration';
            $('.w3tcnr_form').find('input').each(function(i) {
                var name = $(this).attr('name');
                var type = $(this).attr('type');
                if (type == 'radio') {
                    if (!$(this).prop('checked'))
                        return;
                }

                if (name)
                    url += '&' + encodeURIComponent(name) + '=' +
                        encodeURIComponent($(this).val());
            });
            $('.w3tcnr_form').find('select').each(function(i) {
                var name = $(this).attr('name');
                url += '&' + encodeURIComponent(name) + '=' +
                    encodeURIComponent($(this).val());
            });

            W3tc_Lightbox.load(url);
        });
});
