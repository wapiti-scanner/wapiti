import { expect } from '@jest/globals';
import {
	SITE_BACKUP_SIZE_GET,
	SITE_BACKUP_SIZE_GET_SUCCESS,
	SITE_BACKUP_SIZE_GET_FAILED,
} from '../../actions/types';
import siteBackupSize from '../site-backup-size';

describe( 'reducer', () => {
	const fixtures = {
		initialState: {
			isFetching: false,
			loaded: false,
			size: null,
			minDaysOfBackupsAllowed: null,
			daysOfBackupsAllowed: null,
			daysOfBackupsSaved: null,
			retentionDays: null,
		},
		fetchingState: {
			isFetching: true,
			loaded: false,
			size: null,
			minDaysOfBackupsAllowed: null,
			daysOfBackupsAllowed: null,
			daysOfBackupsSaved: null,
			retentionDays: null,
		},
		failedState: {
			isFetching: false,
			loaded: true,
			size: null,
			minDaysOfBackupsAllowed: null,
			daysOfBackupsAllowed: null,
			daysOfBackupsSaved: null,
			retentionDays: null,
		},
	};

	describe( 'siteBackupSize()', () => {
		it.each( [
			{
				state: undefined,
				action: {},
				expected: fixtures.initialState,
			},
			{
				state: fixtures.initialState,
				action: { type: SITE_BACKUP_SIZE_GET },
				expected: fixtures.fetchingState,
			},
			{
				state: fixtures.initialState,
				action: {
					type: SITE_BACKUP_SIZE_GET_SUCCESS,
					payload: {
						size: 10737418240,
						minDaysOfBackupsAllowed: 7,
						daysOfBackupsAllowed: 30,
						daysOfBackupsSaved: 24,
						retentionDays: 7,
					},
				},
				expected: {
					isFetching: false,
					loaded: true,
					size: 10737418240,
					minDaysOfBackupsAllowed: 7,
					daysOfBackupsAllowed: 30,
					daysOfBackupsSaved: 24,
					retentionDays: 7,
				},
			},
			{
				state: fixtures.initialState,
				action: {
					type: SITE_BACKUP_SIZE_GET_FAILED,
				},
				expected: fixtures.failedState,
			},
		] )( 'should return expected state', ( { state, action, expected } ) => {
			expect( siteBackupSize( state, action ) ).toEqual( expected );
		} );
	} );
} );
