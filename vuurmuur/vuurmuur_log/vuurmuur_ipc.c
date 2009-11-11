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
ClearIPC (const int debuglvl, int *shm_id)
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
