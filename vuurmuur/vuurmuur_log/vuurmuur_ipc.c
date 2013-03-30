/***************************************************************************
 *   Copyright (C) 2003-2008 by Victor Julien                              *
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

/** 
 *  \file
 *  \brief Implements functions to communicate through IPC with other
 *         vuurmuur programs.
 */

#include "vuurmuur_log.h"
#include "vuurmuur_ipc.h"

static union semun     semarg;
static ushort          seminit[] = { 1,0 };

int
SetupVMIPC (int *shm_id, struct vrmr_shm_table **shm_table)
{

    char            *shmp;

    /* create shared memory segment */
    *shm_id = shmget(IPC_PRIVATE, sizeof(**shm_table), 0600);
    if(*shm_id < 0)
    {
        vrmr_error(-1, "Error", "unable to create shared memory: %s.", strerror(errno));
        return (-1);
    }

    /* for some reason on my machine the shm_id is zero when vuurmuur is started at boot
       if we sleep for some time and retry it works */
    else if(*shm_id == 0)
    {
        /* sleep 3 seconds before trying again */
        (void)sleep(3);

        *shm_id = shmget(IPC_PRIVATE, sizeof(**shm_table), 0600);
        if(shm_id < 0)
        {
            vrmr_error(-1, "Error", "Unable to create shared memory: %s (retry).", strerror(errno));
            return (-1);
        }
        else if(*shm_id == 0)
        {
            vrmr_info("Info", "Still no valid shm_id. Giving up.");
        }
        else
        {
            vrmr_info("Info", "Creating shared memory successfull: shm_id: %d (retry).", *shm_id);
        }
    }
    else
    {
        vrmr_debug(__FUNC__, "Creating shared memory successfull: shm_id: %d.", *shm_id);
    }

    /* now attach to the shared mem */
    if(*shm_id > 0)
    {
        shmp = shmat(*shm_id, 0, 0);
        if(shmp == (char *)(-1))
        {
            vrmr_error(-1, "Error", "unable to attach to shared memory: %s.", strerror(errno));
            exit(EXIT_FAILURE);
        }
        else
        {
            *shm_table = (struct vrmr_shm_table *)shmp;
            vrmr_info("Info", "Attaching to shared memory successfull.");
        }

        /* if all went well we create a semaphore */
        if(*shm_table)
        {
            sem_id = semget(IPC_PRIVATE, 2, 0600);
            if(sem_id == -1)
            {
                vrmr_error(-1, "Error", "Unable to create semaphore: %s.", strerror(errno));
                return (-1);
            }
            else
            {
                vrmr_info("Info", "Creating a semaphore success: %d", sem_id);
            }

            semarg.array = seminit;
            if(semctl(sem_id, 0, SETALL, semarg) == -1)
            {
                vrmr_error(-1, "Error", "Unable to initialize semaphore: %s.", strerror(errno));
                return (-1);
            }
            else
            {
                vrmr_info("Info", "Initializing the semaphore successfull.");
            }

            /* now initialize the shared mem */
            if(vrmr_lock(sem_id))
            {
                (*shm_table)->sem_id = sem_id;
                (*shm_table)->backend_changed = 0;
                (*shm_table)->reload_result = VRMR_RR_READY;

                vrmr_unlock(sem_id);
            }
        }
    }
    return (0);
}

int
ClearVMIPC (const int debuglvl, int shm_id)
{
    /* destroy shm */
    vrmr_info("Info", "Destroying shared memory...");

    if(shmctl(shm_id, IPC_RMID, NULL) < 0)
    {
        vrmr_error(-1, "Error", "destroying shared memory failed: %s.", strerror(errno));
        return (-1);
    }

    if(debuglvl >= LOW)
        vrmr_debug(__FUNC__, "shared memory destroyed.");

    /* destroy semaphore */
    if(semctl(sem_id, 0, IPC_RMID, semarg) == -1)
    {
        vrmr_error(-1, "Error", "failed to remove semaphore.");
        return (-1);
    }

    return (0);
}

/**
 *  \retval 1 reload
 *  \retval 0 don't reload
 */
int
CheckVMIPC (const int debuglvl, struct vrmr_shm_table *shm_table)
{
    int retval = 0;

    /* check the shm for changes */
    if(vrmr_lock(sem_id))
    {
        if(shm_table->configtool.connected == 1)
        {
            vrmr_info("Info", "Configtool connected: %s.", shm_table->configtool.name);
            shm_table->configtool.connected = 2;
        }
        else if(shm_table->configtool.connected == 3)
        {
            vrmr_info("Info", "Configtool disconnected: %s.", shm_table->configtool.name);
            shm_table->configtool.connected = 0;
        }

        if(shm_table->backend_changed == 1)
        {
            vrmr_audit("IPC-SHM: backend changed: reload (user: %s).", shm_table->configtool.username);
            retval = 1;
            shm_table->backend_changed = 0;

            /* start at 0% */
            shm_table->reload_progress = 0;
        }

        vrmr_unlock(sem_id);
    }
    return (retval);
}

int
WaitVMIPCACK (int wait_time, int *result, struct vrmr_shm_table *shm_table, int *reload)
{
    int     waited = 0;

    if(vrmr_lock(sem_id))
    {
        /* finished so 100% */
        shm_table->reload_progress = 100;

        /* tell the caller about the reload result */
        if(*result < 0)
        {
            shm_table->reload_result = VRMR_RR_ERROR;
        }
        else if(*result == 0)
        {
            shm_table->reload_result = VRMR_RR_SUCCES;
        }
        else
        {
            shm_table->reload_result = VRMR_RR_NOCHANGES;
        }
        vrmr_unlock(sem_id);
    }
    *reload = 0;

    vrmr_info("Info", "Waiting for an VRMR_RR_RESULT_ACK");

    *result = 0;
    waited = 0;

    /* now wait max wait_time seconds for an ACK from the caller */
    while(*result == 0 && waited < wait_time)
    {
        if(vrmr_lock(sem_id))
        {
            /* ah, we got one */
            if(shm_table->reload_result == VRMR_RR_RESULT_ACK)
            {
                shm_table->reload_result = VRMR_RR_READY;
                shm_table->reload_progress = 0;
                *result = 1;

                vrmr_info("Info", "We got an VRMR_RR_RESULT_ACK!");
            }
            vrmr_unlock(sem_id);
        }

        waited++;
        sleep(1);
    }
    if (*result == 0)
    {
        vrmr_info("Info", "We've waited for 30 seconds for an VRMR_RR_RESULT_ACK, but got none. Setting to VRMR_RR_READY");
        if(vrmr_lock(sem_id))
        {
            shm_table->reload_result = VRMR_RR_READY;
            shm_table->reload_progress = 0;
            vrmr_unlock(sem_id);
        }
        else
        {
            vrmr_info("Info", "Hmmmm, failed to set to ready. Did the client crash?");
        }
    }
    return *result;
}

