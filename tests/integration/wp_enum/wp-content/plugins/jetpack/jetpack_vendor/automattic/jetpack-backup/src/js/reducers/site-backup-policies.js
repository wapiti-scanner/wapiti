import {
	SITE_BACKUP_POLICIES_GET,
	SITE_BACKUP_POLICIES_GET_SUCCESS,
	SITE_BACKUP_POLICIES_GET_FAILED,
} from '../actions/types';

const initialState = {
	isFetching: false,
	loaded: false,
	activityLogLimitDays: null,
	storageLimitBytes: null,
};

const siteBackupPolicies = ( state = initialState, action ) => {
	switch ( action.type ) {
		case SITE_BACKUP_POLICIES_GET: {
			return {
				...state,
				isFetching: true,
				loaded: false,
			};
		}

		case SITE_BACKUP_POLICIES_GET_SUCCESS: {
			return {
				...state,
				isFetching: false,
				loaded: true,
				activityLogLimitDays: action.payload.activityLogLimitDays,
				storageLimitBytes: action.payload.storageLimitBytes,
			};
		}
		case SITE_BACKUP_POLICIES_GET_FAILED: {
			return {
				...state,
				isFetching: false,
				loaded: true,
			};
		}
		default:
			return state;
	}
};

export default siteBackupPolicies;
