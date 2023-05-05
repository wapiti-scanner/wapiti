jQuery(function($) {
	function w3tc_extension_cloudflare_resize(o) {
		o.options.height = jQuery('.w3tc_extension_cloudflare_form').height() + 30;
		o.resize();
	}


	$('body')
		/**
		 * Authorize popup
		 */
		.on('click', '.w3tc_extension_cloudflare_authorize', function() {
		    W3tc_Lightbox.open({
		        id:'w3tc-overlay',
		        close: '',
		        width: 800,
		        height: 300,
		        url: ajaxurl + '?action=w3tc_ajax&_wpnonce=' + w3tc_nonce +
            		'&w3tc_action=extension_cloudflare_intro',
		        callback: w3tc_extension_cloudflare_resize
		    });
		})



		.on('click', '.w3tc_popup_submit', function() {
			var url = ajaxurl + '?action=w3tc_ajax&_wpnonce=' + w3tc_nonce;

	    	W3tc_Lightbox.load_form(url, '.w3tc_extension_cloudflare_form',
	    		w3tc_extension_cloudflare_resize);
	    })



		.on('click', '.w3tc_cloudflare_zone_page', function() {
			var page = jQuery(this).data('page');
			jQuery('input[name="w3tc_action"]').val('extension_cloudflare_intro_done');
			jQuery('input[name="page"]').val(page);

			var url = ajaxurl + '?action=w3tc_ajax&_wpnonce=' + w3tc_nonce;

	    	W3tc_Lightbox.load_form(url, '.w3tc_extension_cloudflare_form',
	    		w3tc_extension_cloudflare_resize);
	    })
});
