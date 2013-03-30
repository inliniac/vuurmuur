/***************************************************************************
 *   Copyright (C) 2005-2008 by Victor Julien                              *
 *   victor@vuurmuur.org                                                   *
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 *                                                                         *
 *   You should have received a copy of the GNU General Public License     *
 *   along with this program; if not, write to the                         *
 *   Free Software Foundation, Inc.,                                       *
 *   59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.             *
 ***************************************************************************/

#include "vuurmuur_script.h"

int
script_apply(const int debuglvl, VuurmuurScript *vr_script)
{
    /* vuurmuur */
    int                 vuurmuur_shmid = 0;
    int                 vuurmuur_semid = -1;
    /*@null@*/
    struct vrmr_shm_table    *vuurmuur_shmtable = NULL;
    char                *vuurmuur_shmp = NULL;

    /* vuurmuur_log */
    int                 vuurmuurlog_shmid = 0;
    int                 vuurmuurlog_semid = -1;
    char                *vuurmuurlog_shmp = NULL;
    /*@null@*/
    struct vrmr_shm_table    *vuurmuurlog_shmtable = NULL;
    int                 vuurmuur_result = 0,
                        vuurmuurlog_result = 0;
    int                 waittime = 0;
    
    int                 vuurmuur_progress = 0,
                        vuurmuurlog_progress = 0;

    char                failed = FALSE;
    int                 retval = 0;

    /* try to connect to vuurmuur trough shm */
    vuurmuur_shmtable = NULL;
    get_vuurmuur_pid("/var/run/vuurmuur.pid", &vuurmuur_shmid);
    if(vuurmuur_shmid > 0)
    {
        /* attach to shared memory */
        vuurmuur_shmp = shmat(vuurmuur_shmid, 0, 0);
        if(vuurmuur_shmp == (char *)(-1))
        {
            vrmr_error(VRS_ERR_COMMAND_FAILED, VR_ERR, "attaching to shared memory failed: %s (in: %s:%d).",
                                            strerror(errno), __FUNC__, __LINE__);
        }
        else
        {
            vuurmuur_shmtable = (struct vrmr_shm_table *)vuurmuur_shmp;
            vuurmuur_semid = vuurmuur_shmtable->sem_id;

            /* now try to connect to the shared memory */
            if(vrmr_lock(vuurmuur_semid))
            {
                vuurmuur_shmtable->configtool.connected = 1;
                (void)strlcpy(vuurmuur_shmtable->configtool.username, user_data.realusername, sizeof(vuurmuur_shmtable->configtool.username));
                snprintf(vuurmuur_shmtable->configtool.name, sizeof(vuurmuur_shmtable->configtool.name), "Vuurmuur_script %s (user: %s)", version_string, user_data.realusername);
                vrmr_unlock(vuurmuur_semid);
            }
            else
            {
                vrmr_error(VRS_ERR_COMMAND_FAILED, VR_ERR, "connecting to Vuurmuur failed: could not lock semid.");
                vuurmuur_shmp = NULL;
            }
        }
    }
    else
    {
        vrmr_warning(VR_WARN, "vuurmuur not notified: connecting failed: no shmid.");
        vuurmuur_shmp = NULL;
    }

    /* try to connect to vuurmuur trough shm */
    vuurmuurlog_shmtable = NULL;
    get_vuurmuur_pid("/var/run/vuurmuur_log.pid", &vuurmuurlog_shmid);
    if(vuurmuurlog_shmid > 0)
    {
        /* attach to shared memory */
        vuurmuurlog_shmp = shmat(vuurmuurlog_shmid, 0, 0);
        if(vuurmuurlog_shmp == (char *)(-1))
        {
            vrmr_error(VRS_ERR_COMMAND_FAILED, VR_ERR, "attaching to shared memory failed: %s (in: %s:%d).",
                                            strerror(errno), __FUNC__, __LINE__);
        }
        else
        {
            vuurmuurlog_shmtable = (struct vrmr_shm_table *)vuurmuurlog_shmp;
            vuurmuurlog_semid = vuurmuurlog_shmtable->sem_id;

            /* now try to connect to the shared memory */
            if(vrmr_lock(vuurmuurlog_semid))
            {
                vuurmuurlog_shmtable->configtool.connected = 1;
                (void)strlcpy(vuurmuurlog_shmtable->configtool.username, user_data.realusername, sizeof(vuurmuurlog_shmtable->configtool.username));
                snprintf(vuurmuurlog_shmtable->configtool.name, sizeof(vuurmuurlog_shmtable->configtool.name), "Vuurmuur_script %s (user: %s)", version_string, user_data.realusername);
                vrmr_unlock(vuurmuurlog_semid);
            }
            else
            {
                vrmr_error(VRS_ERR_COMMAND_FAILED, VR_ERR, "connecting to Vuurmuur_log failed: could not lock semid.");
                vuurmuurlog_shmp = NULL;
            }
        }
    }
    else
    {
        vrmr_warning(VR_WARN, "vuurmuur_log not notified: connecting failed: no shmid.");
        vuurmuurlog_shmp = NULL;
    }

    /* handle no vuurmuur connection */
    if(vuurmuur_shmtable != NULL && vuurmuur_semid != -1)
    {
        if(vrmr_lock(vuurmuur_semid))
        {
            vuurmuur_shmtable->backend_changed = 1;
            vrmr_unlock(vuurmuur_semid);

            vuurmuur_result = VRMR_RR_NO_RESULT_YET;
        }
    }
    else
    {
        vuurmuur_result = VRMR_RR_READY;
    }

    /* handle no vuurmuur_log connection */
    if(vuurmuurlog_shmtable != NULL && vuurmuurlog_semid != -1)
    {
        if(vrmr_lock(vuurmuurlog_semid))
        {
            vuurmuurlog_shmtable->backend_changed = 1;
            vrmr_unlock(vuurmuurlog_semid);

            vuurmuurlog_result = VRMR_RR_NO_RESULT_YET;
        }
    }
    else
    {
        vuurmuurlog_result = VRMR_RR_READY;
    }

    /* wait max 60 seconds */
    while (((vuurmuur_result == VRMR_RR_NO_RESULT_YET || vuurmuur_result == VRMR_RR_RESULT_ACK) ||
                (vuurmuurlog_result == VRMR_RR_NO_RESULT_YET || vuurmuurlog_result == VRMR_RR_RESULT_ACK))
            && waittime < 60000000)
    {
        if(vuurmuur_shmtable != NULL && vuurmuur_semid != -1) {
            if(vuurmuur_progress < 100)
            {
                if(vrmr_lock(vuurmuur_semid))
                {
                    if(vuurmuur_shmtable->reload_result != VRMR_RR_READY)
                    {
                        vuurmuur_result   = vuurmuur_shmtable->reload_result;
                    }
                    vuurmuur_progress = vuurmuur_shmtable->reload_progress;

                    vrmr_unlock(vuurmuur_semid);
                }
            }

            if(vuurmuur_progress == 100)
            {
                if(vuurmuur_semid == -1)
                {
                    vuurmuur_result = VRMR_RR_READY;
                    failed = 1;
                }
                else if(vrmr_lock(vuurmuur_semid))
                {
                    vuurmuur_shmtable->reload_result = VRMR_RR_RESULT_ACK;
                    vrmr_unlock(vuurmuur_semid);

                    if(vuurmuur_result != VRMR_RR_SUCCES && vuurmuur_result != VRMR_RR_NOCHANGES)
                    {
                        vuurmuur_result = VRMR_RR_READY;
                        failed = 1;
                    }
                }
            }
        } else {
            vuurmuur_result = VRMR_RR_READY;
            failed = 1;
        }

        if(vuurmuurlog_shmtable != NULL && vuurmuurlog_semid != -1) {
            if(vuurmuurlog_progress < 100)
            {
                if(vrmr_lock(vuurmuurlog_semid))
                {
                    if(vuurmuurlog_shmtable->reload_result != VRMR_RR_READY)
                    {
                        vuurmuurlog_result = vuurmuurlog_shmtable->reload_result;
                    }
                    vuurmuurlog_progress = vuurmuurlog_shmtable->reload_progress;

                    vrmr_unlock(vuurmuurlog_semid);
                }
            }

            if(vuurmuurlog_progress == 100)
            {
                if(vuurmuurlog_semid == -1)
                {
                }
                else if(vrmr_lock(vuurmuurlog_semid))
                {
                    vuurmuurlog_shmtable->reload_result = VRMR_RR_RESULT_ACK;
                    vrmr_unlock(vuurmuurlog_semid);

                    if(vuurmuurlog_result != VRMR_RR_SUCCES && vuurmuur_result != VRMR_RR_NOCHANGES)
                    {
                        vuurmuurlog_result = VRMR_RR_READY;
                        failed = 1;
                    }
                }
            } else {
                vuurmuurlog_result = VRMR_RR_READY;
                failed = 1;
            }
        }

        /* no result yet, sleep 1 sec, or if the server didn't have a chance to do anything */
        if( (vuurmuur_result    == VRMR_RR_NO_RESULT_YET || vuurmuur_result    == VRMR_RR_RESULT_ACK) ||
            (vuurmuurlog_result == VRMR_RR_NO_RESULT_YET || vuurmuurlog_result == VRMR_RR_RESULT_ACK))
        {
            waittime += 1000;
            usleep(1000);
        }
    }

    /* timed out */
    if(vuurmuur_progress < 100)
    {
        failed = 1;
    }

    /* timed out */
    if(vuurmuurlog_progress < 100)
    {
        failed = 1;
    }

    /* detach from shared memory, if we were attached */
    if(vuurmuur_shmp != NULL && vuurmuur_shmp != (char *)(-1) && vuurmuur_shmtable != 0)
    {
        if(vrmr_lock(vuurmuur_semid))
        {
            vuurmuur_shmtable->configtool.connected = 3;
            vrmr_unlock(vuurmuur_semid);
        }
        (void)shmdt(vuurmuur_shmp);
    }
    if(vuurmuurlog_shmp != NULL && vuurmuurlog_shmp != (char *)(-1) && vuurmuurlog_shmtable != 0)
    {
        if(vrmr_lock(vuurmuurlog_semid))
        {
            vuurmuurlog_shmtable->configtool.connected = 3;
            vrmr_unlock(vuurmuurlog_semid);
        }
        (void)shmdt(vuurmuurlog_shmp);
    }

    if(failed == TRUE)
        retval = VRS_ERR_COMMAND_FAILED;

    return(retval);
}
