jQuery(function($) {
	function w3tchw_resize(o) {
		o.options.height = jQuery('.w3tc_cdn_highwinds_form').height() + 30;
		o.resize();
	}

	$('body')
		.on('click', '.w3tc_cdn_highwinds_authorize', function() {
		    W3tc_Lightbox.open({
		        id:'w3tc-overlay',
		        close: '',
		        width: 800,
		        height: 300,
		        url: ajaxurl + '?action=w3tc_ajax&_wpnonce=' + w3tc_nonce +
            		'&w3tc_action=cdn_highwinds_authenticate',
		        callback: w3tchw_resize
		    });
		})



		.on('click', '.w3tc_cdn_highwinds_select_host', function() {
			var url = ajaxurl + '?action=w3tc_ajax&_wpnonce=' + w3tc_nonce +
        		'&w3tc_action=cdn_highwinds_select_host';

			var v = $('.w3tc_cdn_highwinds_form').find('input').each(function(i) {
				var name = $(this).attr('name');
				if (name)
					url += '&' + encodeURIComponent(name) + '=' +
						encodeURIComponent($(this).val());
			});

	    	W3tc_Lightbox.load(url, w3tchw_resize);
	    })



	    .on('click', '.w3tc_cdn_highwinds_configure_host', function() {
			var url = ajaxurl + '?action=w3tc_ajax&_wpnonce=' + w3tc_nonce +
        		'&w3tc_action=cdn_highwinds_configure_host';

			var v = $('.w3tc_cdn_highwinds_form').find('input').each(function(i) {
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

	    	W3tc_Lightbox.load(url, w3tchw_resize);
	    })



	    .on('click', '.w3tc_cdn_highwinds_configure_cnames_form', function() {
			W3tc_Lightbox.open({
		        id:'w3tc-overlay',
		        close: '',
		        width: 1000,
		        height: 400,
		        url: ajaxurl + '?action=w3tc_ajax&_wpnonce=' + w3tc_nonce +
            		'&w3tc_action=cdn_highwinds_configure_cnames_form',
		        callback: function(o) {
		        	w3tchw_resize(o);
		        	w3tc_cdn_cnames_assign();
		        }
		    });
	    })



	    .on('click', '.w3tc_cdn_highwinds_configure_cnames', function() {
	    	var url = ajaxurl + '?action=w3tc_ajax&_wpnonce=' + w3tc_nonce +
        		'&w3tc_action=cdn_highwinds_configure_cnames';

			var v = $('.w3tc_cdn_highwinds_form').find('input').each(function(i) {
				var name = $(this).attr('name');

				if (name)
					url += '&' + encodeURIComponent(name) + '=' +
						encodeURIComponent($(this).val());
			});

	    	W3tc_Lightbox.load(url, function(o) {
	        	w3tchw_resize(o);
	        	w3tc_cdn_cnames_assign();
	        });
	    })



	    .on('size_change', '#cdn_cname_add', function() {
	    	w3tchw_resize(W3tc_Lightbox);
	    })
});
