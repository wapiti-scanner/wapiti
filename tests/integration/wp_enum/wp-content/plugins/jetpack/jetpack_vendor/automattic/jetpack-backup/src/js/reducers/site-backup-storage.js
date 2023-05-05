import { SITE_BACKUP_STORAGE_ADDON_OFFER_SET, SITE_BACKUP_STORAGE_SET } from '../actions/types';

const initialState = {
	usageLevel: null,
	addonOfferSlug: null,
};

const siteBackupStorage = ( state = initialState, action ) => {
	switch ( action.type ) {
		case SITE_BACKUP_STORAGE_SET:
			return {
				...state,
				usageLevel: action.usageLevel ?? null,
			};
		case SITE_BACKUP_STORAGE_ADDON_OFFER_SET:
			return {
				...state,
				addonOfferSlug: action.addonOfferSlug ?? null,
			};
	}

	return state;
};

export default siteBackupStorage;
