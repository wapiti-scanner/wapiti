import {
	SITE_BACKUP_SIZE_GET,
	SITE_BACKUP_SIZE_GET_SUCCESS,
	SITE_BACKUP_SIZE_GET_FAILED,
} from '../actions/types';

const initialState = {
	isFetching: false,
	loaded: false,
	size: null,
	minDaysOfBackupsAllowed: null,
	daysOfBackupsAllowed: null,
	daysOfBackupsSaved: null,
	retentionDays: null,
};

const siteBackupSize = ( state = initialState, action ) => {
	switch ( action.type ) {
		case SITE_BACKUP_SIZE_GET: {
			return {
				...state,
				isFetching: true,
				loaded: false,
			};
		}

		case SITE_BACKUP_SIZE_GET_SUCCESS: {
			return {
				...state,
				isFetching: false,
				loaded: true,
				size: action.payload?.size,
				minDaysOfBackupsAllowed: action.payload?.minDaysOfBackupsAllowed,
				daysOfBackupsAllowed: action.payload?.daysOfBackupsAllowed,
				daysOfBackupsSaved: action.payload?.daysOfBackupsSaved,
				retentionDays: action.payload?.retentionDays,
			};
		}
		case SITE_BACKUP_SIZE_GET_FAILED: {
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

export default siteBackupSize;
