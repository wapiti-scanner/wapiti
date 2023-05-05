import apiFetch from '@wordpress/api-fetch';
import { useDispatch, useSelect } from '@wordpress/data';
import { useState, useEffect } from '@wordpress/element';
import { STORE_ID } from '../../../store';

const useAddonStorageOffer = () => {
	const addonSlug = useSelect( select => select( STORE_ID ).getStorageAddonOfferSlug() );
	const [ addonSizeText, setAddonSizeText ] = useState( null );
	const [ addonPricing, setAddonPricing ] = useState( null );
	const storageLimit = useSelect( select => select( STORE_ID ).getBackupStorageLimit() );
	const storageSize = useSelect( select => select( STORE_ID ).getBackupSize() );
	const dispatch = useDispatch( STORE_ID );
	const [ addOnLoaded, setAddonLoaded ] = useState( false );

	const fetchAddOnOffer = () =>
		apiFetch( {
			path: `/jetpack/v4/site/backup/addon-offer?storage_size=${ storageSize }&storage_limit=${ storageLimit }`,
		} ).then(
			res => {
				if ( res.slug && res.pricing && res.size_text ) {
					dispatch.setAddonStorageOfferSlug( res.slug );
					setAddonSizeText( res.size_text );
					setAddonPricing( res.pricing );
					setAddonLoaded( true );
				}
			},
			() => {
				setAddonLoaded( false );
			}
		);

	// Start the initial state fetch
	useEffect( () => {
		fetchAddOnOffer();
	}, [ storageSize, storageLimit ] ); // eslint-disable-line react-hooks/exhaustive-deps

	return {
		addonSlug,
		addonSizeText,
		addonPricing,
		addOnLoaded,
	};
};

export default useAddonStorageOffer;
