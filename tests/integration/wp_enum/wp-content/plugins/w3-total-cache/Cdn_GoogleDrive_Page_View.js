jQuery(function($) {
    $('.w3tc_cdn_google_drive_authorize').click(function() {
        window.location = w3tc_cdn_google_drive_url[0];
    });

    if (window.w3tc_cdn_google_drive_popup_url) {
	    W3tc_Lightbox.open({
	        id:'w3tc-overlay',
	        close: '',
	        width: 800,
	        height: 500,
	        url: w3tc_cdn_google_drive_popup_url[0],
	        onClose: function() {
	        }
	    });
    }
});
