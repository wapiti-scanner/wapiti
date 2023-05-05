jQuery(function($) {
	function w3tc_stackpath_resize(o) {
		o.options.height = jQuery('.w3tc_cdn_stackpath2_fsd_form').height();
		o.resize();
	}

	$('body')
		.on('click', '.w3tc_cdn_stackpath2_fsd_authorize', function() {
		    W3tc_Lightbox.open({
		        id:'w3tc-overlay',
		        close: '',
		        width: 800,
		        height: 300,
		        url: ajaxurl + '?action=w3tc_ajax&_wpnonce=' + w3tc_nonce +
            		'&w3tc_action=cdn_stackpath2_fsd_intro',
		        callback: w3tc_stackpath_resize
		    });
		})



		.on('click', '.w3tc_cdn_stackpath2_fsd_list_stacks', function() {
			var url = ajaxurl + '?action=w3tc_ajax&_wpnonce=' + w3tc_nonce +
        		'&w3tc_action=cdn_stackpath2_fsd_list_stacks';

			W3tc_Lightbox.load_form(url, '.w3tc_cdn_stackpath2_fsd_form', w3tc_stackpath_resize);
	    })



		.on('click', '.w3tc_cdn_stackpath2_fsd_list_sites', function() {
			var url = ajaxurl + '?action=w3tc_ajax&_wpnonce=' + w3tc_nonce +
        		'&w3tc_action=cdn_stackpath2_fsd_list_sites';

			W3tc_Lightbox.load_form(url, '.w3tc_cdn_stackpath2_fsd_form', w3tc_stackpath_resize);
	    })



	    .on('click', '.w3tc_cdn_stackpath2_fsd_view_site', function() {
			var url = ajaxurl + '?action=w3tc_ajax&_wpnonce=' + w3tc_nonce +
        		'&w3tc_action=cdn_stackpath2_fsd_view_site';

			W3tc_Lightbox.load_form(url, '.w3tc_cdn_stackpath2_fsd_form', w3tc_stackpath_resize);
	    })



	    .on('click', '.w3tc_cdn_stackpath2_fsd_configure_site', function() {
			var url = ajaxurl + '?action=w3tc_ajax&_wpnonce=' + w3tc_nonce +
        		'&w3tc_action=cdn_stackpath2_fsd_configure_site';

    		W3tc_Lightbox.load_form(url, '.w3tc_cdn_stackpath2_fsd_form', w3tc_stackpath_resize);
	    })



	    .on('click', '.w3tc_cdn_stackpath2_fsd_configure_site_skip', function() {
			var url = ajaxurl + '?action=w3tc_ajax&_wpnonce=' + w3tc_nonce +
        		'&w3tc_action=cdn_stackpath2_fsd_configure_site_skip';

			W3tc_Lightbox.load_form(url, '.w3tc_cdn_stackpath2_fsd_form', w3tc_stackpath_resize);
	    })



	    .on('click', '.w3tc_cdn_stackpath2_fsd_done', function() {
			// refresh page
	    	window.location = window.location + '&';
	    })
});
