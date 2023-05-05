jQuery(function($) {
	function w3tc_rackspace_resize(o) {
		o.options.height = jQuery('.w3tc_cdn_rackspace_form').height() + 30;
		o.resize();
	}


	function w3tc_rackspace_created(o) {
		w3tc_rackspace_resize(o);
		w3tc_rackspace_check_service_state();
	}



	function w3tc_rackspace_check_service_state() {
	    var service_id = jQuery('input[name="service_id"]').val();
	    var access_token = jQuery('input[name="access_token"]').val();
	    var access_region_descriptor = jQuery('input[name="access_region_descriptor"]').val();

	    jQuery.post(ajaxurl,
	    	{
		    	'action': 'w3tc_ajax',
		    	'_wpnonce': w3tc_nonce,
		    	'service_id': service_id,
		    	'access_token': access_token,
		    	'access_region_descriptor': access_region_descriptor,
		        'w3tc_action': 'cdn_rackspace_service_get_state'
		    }, function(data) {
	            var state = 'unknown';
	            if (data && data['status'])
	            	status = data['status'];

	            jQuery('.w3tc_rackspace_created_status').html(status);

	            if (status == 'deployed')
	            	w3tc_rackspace_service_created_done(data);
	            else
	            	setTimeout(w3tc_rackspace_check_service_state, 5000);
	        }, 'json'
	    ).fail(function() {
	        jQuery('.w3tc_rackspace_created_state').html('Failed to obtain state');
	        setTimeout(w3tc_rackspace_check_service_state, 5000);
	    });
	}



	function w3tc_rackspace_service_created_done(data) {
		jQuery('.w3tc_rackspace_cname').html(data['cname']);
		jQuery('.w3tc_rackspace_access_url').html(data['access_url']);
		jQuery('.w3tc_rackspace_created_in_progress').css('display', 'none');
		jQuery('.w3tc_rackspace_created_done').css('display', '');

		w3tc_rackspace_resize(W3tc_Lightbox);
	}



	$('body')
		/**
		 * Authorize popup
		 */
		.on('click', '.w3tc_cdn_rackspace_authorize', function() {
		    W3tc_Lightbox.open({
		        id:'w3tc-overlay',
		        close: '',
		        width: 800,
		        height: 300,
		        url: ajaxurl + '?action=w3tc_ajax&_wpnonce=' + w3tc_nonce +
            		'&w3tc_action=cdn_rackspace_intro',
		        callback: w3tc_rackspace_resize
		    });
		})



		.on('click', '.w3tc_popup_submit', function() {
			var url = ajaxurl + '?action=w3tc_ajax&_wpnonce=' + w3tc_nonce;

	    	W3tc_Lightbox.load_form(url, '.w3tc_cdn_rackspace_form',
	    		w3tc_rackspace_resize);
	    })



	    .on('click', '.w3tc_cdn_rackspace_service_create_done', function() {
			var url = ajaxurl + '?action=w3tc_ajax&_wpnonce=' + w3tc_nonce +
        		'&w3tc_action=cdn_rackspace_service_create_done';

	    	W3tc_Lightbox.load_form(url, '.w3tc_cdn_rackspace_form',
	    		w3tc_rackspace_created);
	    })



	    .on('click', '.w3tc_cdn_rackspace_protocol', function() {
	    	var protocol = '';

   	        $('body').find('.w3tc_cdn_rackspace_protocol').each(function(i) {
                if (!jQuery(this).prop('checked'))
                    return;

				protocol = $(this).val();
        	});

	    	//alert('ha ' + protocol);

        	$('.w3tc_cdn_rackspace_cname_http').css('display',
        		(protocol == 'http' ? '' : 'none'));
        	$('.w3tc_cdn_rackspace_cname_https').css('display',
        		(protocol == 'https' ? '' : 'none'));
	    })



	    /**
	     * CNAMEs popup
	     */
	    .on('click', '.w3tc_cdn_rackspace_configure_domains', function() {
			W3tc_Lightbox.open({
		        id:'w3tc-overlay',
		        close: '',
		        width: 1000,
		        height: 400,
		        url: ajaxurl + '?action=w3tc_ajax&_wpnonce=' + w3tc_nonce +
            		'&w3tc_action=cdn_rackspace_configure_domains',
		        callback: function(o) {
		        	w3tc_rackspace_resize(o);
		        	w3tc_cdn_cnames_assign();
		        }
		    });
	    })



	    .on('click', '.w3tc_cdn_rackspace_configure_domains_done', function() {
	    	var url = ajaxurl + '?action=w3tc_ajax&_wpnonce=' + w3tc_nonce +
        		'&w3tc_action=cdn_rackspace_configure_domains_done';

			var v = $('.w3tc_cdn_rackspace_form').find('input').each(function(i) {
				var name = $(this).attr('name');

				if (name)
					url += '&' + encodeURIComponent(name) + '=' +
						encodeURIComponent($(this).val());
			});

	    	W3tc_Lightbox.load(url, function(o) {
	        	w3tc_rackspace_resize(o);
	        	w3tc_cdn_cnames_assign();
	        });
	    })



	    .on('size_change', '#cdn_cname_add', function() {
	    	w3tc_rackspace_resize(W3tc_Lightbox);
	    })
});
