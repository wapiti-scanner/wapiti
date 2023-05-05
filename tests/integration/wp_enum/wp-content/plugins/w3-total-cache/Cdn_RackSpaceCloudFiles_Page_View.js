jQuery(function($) {
	function w3tc_rackspace_resize(o) {
		o.options.height = jQuery('.w3tc_cdn_rackspace_form').height() + 30;
		o.resize();
	}

	$('body')
		.on('click', '.w3tc_cdn_rackspace_authorize', function() {
		    W3tc_Lightbox.open({
		        id:'w3tc-overlay',
		        close: '',
		        width: 800,
		        height: 300,
		        url: ajaxurl + '?action=w3tc_ajax&_wpnonce=' + w3tc_nonce +
            		'&w3tc_action=cdn_rackspace_authenticate',
		        callback: w3tc_rackspace_resize
		    });
		})



		.on('click', '.w3tc_popup_submit', function() {
			var url = ajaxurl + '?action=w3tc_ajax&_wpnonce=' + w3tc_nonce;

	    	W3tc_Lightbox.load_form(url, '.w3tc_cdn_rackspace_form',
	    		w3tc_rackspace_resize);
	    })
});
