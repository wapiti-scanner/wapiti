jQuery(function($) {
	function w3tc_stackpath_resize(o) {
		o.options.height = jQuery('.w3tc_cdn_stackpath_form').height();
		o.resize();
	}

	$('body')
		.on('click', '.w3tc_cdn_stackpath_authorize', function() {
		    W3tc_Lightbox.open({
		        id:'w3tc-overlay',
		        close: '',
		        width: 800,
		        height: 300,
		        url: ajaxurl + '?action=w3tc_ajax&_wpnonce=' + w3tc_nonce +
            		'&w3tc_action=cdn_stackpath_intro',
		        callback: w3tc_stackpath_resize
		    });
		})



		.on('click', '.w3tc_cdn_stackpath_list_zones', function() {
			var url = ajaxurl + '?action=w3tc_ajax&_wpnonce=' + w3tc_nonce +
        		'&w3tc_action=cdn_stackpath_list_zones';

			W3tc_Lightbox.load_form(url, '.w3tc_cdn_stackpath_form', w3tc_stackpath_resize);
	    })



	    .on('click', '.w3tc_cdn_stackpath_view_zone', function() {
			var url = ajaxurl + '?action=w3tc_ajax&_wpnonce=' + w3tc_nonce +
        		'&w3tc_action=cdn_stackpath_view_zone';

			W3tc_Lightbox.load_form(url, '.w3tc_cdn_stackpath_form', w3tc_stackpath_resize);
	    })



	    .on('click', '.w3tc_cdn_stackpath_configure_zone', function() {
			var url = ajaxurl + '?action=w3tc_ajax&_wpnonce=' + w3tc_nonce +
        		'&w3tc_action=cdn_stackpath_configure_zone';

    		W3tc_Lightbox.load_form(url, '.w3tc_cdn_stackpath_form', w3tc_stackpath_resize);
	    })



	    .on('click', '.w3tc_cdn_stackpath_configure_zone_skip', function() {
			var url = ajaxurl + '?action=w3tc_ajax&_wpnonce=' + w3tc_nonce +
        		'&w3tc_action=cdn_stackpath_configure_zone_skip';

			W3tc_Lightbox.load_form(url, '.w3tc_cdn_stackpath_form', w3tc_stackpath_resize);
	    })



	    .on('click', '.w3tc_cdn_stackpath_done', function() {
			// refresh page
	    	window.location = window.location + '&';
	    })
});
