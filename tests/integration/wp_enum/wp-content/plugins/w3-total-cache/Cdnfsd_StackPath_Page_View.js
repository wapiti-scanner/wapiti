jQuery(function($) {
	function w3tc_stackpath_fsd_resize(o) {
		o.options.height = jQuery('.w3tc_popup_form').height() + 30;
		o.resize();
	}

	$('body')
		.on('click', '.w3tc_cdn_stackpath_fsd_authorize', function() {
		    W3tc_Lightbox.open({
		        id:'w3tc-overlay',
		        close: '',
		        width: 800,
		        height: 300,
		        url: ajaxurl + '?action=w3tc_ajax&_wpnonce=' + w3tc_nonce +
            		'&w3tc_action=cdn_stackpath_fsd_intro',
		        callback: w3tc_stackpath_fsd_resize
		    });
		})



		.on('click', '.w3tc_cdn_stackpath_fsd_list_zones', function() {
			var url = ajaxurl + '?action=w3tc_ajax&_wpnonce=' + w3tc_nonce +
        		'&w3tc_action=cdn_stackpath_fsd_list_zones';

			var v = $('.w3tc_popup_form').find('input').each(function(i) {
				var name = $(this).attr('name');
				if (name)
					url += '&' + encodeURIComponent(name) + '=' +
						encodeURIComponent($(this).val());
			});

	    	W3tc_Lightbox.load(url, w3tc_stackpath_fsd_resize);
	    })



	    .on('click', '.w3tc_cdn_stackpath_fsd_view_zone', function() {
			var url = ajaxurl + '?action=w3tc_ajax&_wpnonce=' + w3tc_nonce +
        		'&w3tc_action=cdn_stackpath_fsd_view_zone';

			var v = $('.w3tc_popup_form').find('input').each(function(i) {
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

	    	W3tc_Lightbox.load(url, w3tc_stackpath_fsd_resize);
	    })



	    .on('click', '.w3tc_cdn_stackpath_fsd_configure_zone', function() {
			var url = ajaxurl + '?action=w3tc_ajax&_wpnonce=' + w3tc_nonce +
        		'&w3tc_action=cdn_stackpath_fsd_configure_zone';

			var v = $('.w3tc_popup_form').find('input').each(function(i) {
				var name = $(this).attr('name');
				if (name)
					url += '&' + encodeURIComponent(name) + '=' +
						encodeURIComponent($(this).val());
			});

	    	W3tc_Lightbox.load(url, w3tc_stackpath_fsd_resize);
	    })



	    .on('click', '.w3tc_cdn_stackpath_fsd_configure_zone_skip', function() {
			var url = ajaxurl + '?action=w3tc_ajax&_wpnonce=' + w3tc_nonce +
        		'&w3tc_action=cdn_stackpath_fsd_configure_zone_skip';

			var v = $('.w3tc_popup_form').find('input').each(function(i) {
				var name = $(this).attr('name');
				if (name)
					url += '&' + encodeURIComponent(name) + '=' +
						encodeURIComponent($(this).val());
			});

	    	W3tc_Lightbox.load(url, w3tc_stackpath_fsd_resize);
	    })



	    .on('click', '.w3tc_cdn_stackpath_fsd_done', function() {
			// refresh page
	    	window.location = window.location + '&';
	    })



	    .on('size_change', '#cdn_cname_add', function() {
	    	w3tc_stackpath_fsd_resize(W3tc_Lightbox);
	    })
});
