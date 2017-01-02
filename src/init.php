<?php
declare(strict_types=1);

namespace OpenIdConnectClient;

/**
 * Start a PHP session if it is not already running.
 */

if (session_id() === '') {
    session_start();
}
