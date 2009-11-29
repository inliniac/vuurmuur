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

/** \file
 * vuurmuur_ipc.c implements functions to communicate through IPC with other
 * vuurmuur programs. */

#include "vuurmuur_log.h"
#include "vuurmuur_ipc.h"

union semun     semarg;
ushort          seminit[] = { 1,0 };

int
SetupVMIPC (int *shm_id, struct SHM_TABLE **shm_table)
{

    char            *shmp;

    /* create shared memory segment */
    *shm_id = shmget(IPC_PRIVATE, sizeof(**shm_table), 0600);
    if(*shm_id < 0)
    {
        (void)vrprint.error(-1, "Error", "unable to create shared memory: %s.", strerror(errno));
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
            (void)vrprint.error(-1, "Error", "Unable to create shared memory: %s (retry).", strerror(errno));
            return (-1);
        }
        else if(*shm_id == 0)
        {
            (void)vrprint.info("Info", "Still no valid shm_id. Giving up.");
        }
        else
        {
            (void)vrprint.info("Info", "Creating shared memory successfull: shm_id: %d (retry).", *shm_id);
        }
    }
    else
    {
        (void)vrprint.debug(__FUNC__, "Creating shared memory successfull: shm_id: %d.", *shm_id);
    }

    /* now attach to the shared mem */
    if(*shm_id > 0)
    {
        shmp = shmat(*shm_id, 0, 0);
        if(shmp == (char *)(-1))
        {
            (void)vrprint.error(-1, "Error", "unable to attach to shared memory: %s.", strerror(errno));
            exit(EXIT_FAILURE);
        }
        else
        {
            *shm_table = (struct SHM_TABLE *)shmp;
            (void)vrprint.info("Info", "Attaching to shared memory successfull.");
        }

        /* if all went well we create a semaphore */
        if(*shm_table)
        {
            sem_id = semget(IPC_PRIVATE, 2, 0600);
            if(sem_id == -1)
            {
                (void)vrprint.error(-1, "Error", "Unable to create semaphore: %s.", strerror(errno));
                return (-1);
            }
            else
            {
                (void)vrprint.info("Info", "Creating a semaphore success: %d", sem_id);
            }

            semarg.array = seminit;
            if(semctl(sem_id, 0, SETALL, semarg) == -1)
            {
                (void)vrprint.error(-1, "Error", "Unable to initialize semaphore: %s.", strerror(errno));
                return (-1);
            }
            else
            {
                (void)vrprint.info("Info", "Initializing the semaphore successfull.");
            }

            /* now initialize the shared mem */
            if(LOCK)
            {
                (*shm_table)->sem_id = sem_id;
                (*shm_table)->backend_changed = 0;
                (*shm_table)->reload_result = VR_RR_READY;

                UNLOCK;
            }
        }
    }
    return (0);
}

int
ClearVMIPC (const int debuglvl, int *shm_id)
{
    /* destroy shm */
    (void)vrprint.info("Info", "Destroying shared memory...");
    if(shmctl(*shm_id, IPC_RMID, NULL) < 0)
    {
        (void)vrprint.error(-1, "Error", "destroying shared memory failed: %s.", strerror(errno));
        return (-1);
    }
    else
    {
        if(debuglvl >= LOW)
            (void)vrprint.debug(__FUNC__, "shared memory destroyed.");
    }

    /* destroy semaphore */
    if(semctl(sem_id, 0, IPC_RMID, semarg) == -1)
    {
        (void)vrprint.error(-1, "Error", "failed to remove semaphore.");
        return (-1);
    }
    return (0);
}

int
CheckVMIPC (const int debuglvl, struct SHM_TABLE **shm_table, int *reload)
{
    /* check the shm for changes */
    if(LOCK)
    {
        if((*shm_table)->configtool.connected == 1)
        {
            (void)vrprint.info("Info", "Configtool connected: %s.", (*shm_table)->configtool.name);
            (*shm_table)->configtool.connected = 2;
        }
        else if((*shm_table)->configtool.connected == 3)
        {
            (void)vrprint.info("Info", "Configtool disconnected: %s.", (*shm_table)->configtool.name);
            (*shm_table)->configtool.connected = 0;
        }

        if((*shm_table)->backend_changed == 1)
        {
            (void)vrprint.audit("IPC-SHM: backend changed: reload (user: %s).", (*shm_table)->configtool.username);
            *reload = 1;
            (*shm_table)->backend_changed = 0;

            /* start at 0% */
            (*shm_table)->reload_progress = 0;
        }

        UNLOCK;
    }
    return (0);
}

int
WaitVMIPCACK (int wait_time, int *result, struct SHM_TABLE **shm_table, int *reload)
{
    int     waited = 0;

    if(LOCK)
    {
        /* finished so 100% */
        (*shm_table)->reload_progress = 100;

        /* tell the caller about the reload result */
        if(*result < 0)
        {
            (*shm_table)->reload_result = VR_RR_ERROR;
        }
        else if(*result == 0)
        {
            (*shm_table)->reload_result = VR_RR_SUCCES;
        }
        else
        {
            (*shm_table)->reload_result = VR_RR_NOCHANGES;
        }
        UNLOCK;
    }
    *reload = 0;

    (void)vrprint.info("Info", "Waiting for an VR_RR_RESULT_ACK");

    *result = 0;
    waited = 0;

    /* now wait max wait_time seconds for an ACK from the caller */
    while(*result == 0 && waited < wait_time)
    {
        if(LOCK)
        {
            /* ah, we got one */
            if((*shm_table)->reload_result == VR_RR_RESULT_ACK)
            {
                (*shm_table)->reload_result = VR_RR_READY;
                (*shm_table)->reload_progress = 0;
                *result = 1;

                (void)vrprint.info("Info", "We got an VR_RR_RESULT_ACK!");
            }
            UNLOCK;
        }

        waited++;
        sleep(1);
    }
    if (*result == 0)
    {
        (void)vrprint.info("Info", "We've waited for 30 seconds for an VR_RR_RESULT_ACK, but got none. Setting to VR_RR_READY");
        if(LOCK)
        {
            (*shm_table)->reload_result = VR_RR_READY;
            (*shm_table)->reload_progress = 0;
            UNLOCK;
        }
        else
        {
            (void)vrprint.info("Info", "Hmmmm, failed to set to ready. Did the client crash?");
        }
    }
    return *result;
}
