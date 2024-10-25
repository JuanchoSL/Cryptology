<?php

declare(strict_types=1);

namespace JuanchoSL\Cryptology;

abstract class AbstractCrypted
{
    /**
     * Check if a string is a regular filepath and exists
     * @param string $origin The string to check
     * @return bool Result of check
     */
    protected function checkForFile(string $origin): bool
    {
        return (is_file($origin) && file_exists($origin));
    }

    /**
     * Return the file contents if is a regular file path and it exists
     * @param string $origin The file path
     * @return string The file contents or the starting string
     */
    protected function getFromFile(string $origin): string
    {
        if ($this->checkForFile($origin)) {
            $origin = file_get_contents($origin);
        }
        return $origin;
    }

    protected function generateFile(string $ext, string $name = null, string $dir = null): string
    {
        if (is_null($dir)) {
            $dir = sys_get_temp_dir();
        }
        if (is_null($name)) {
            $name = bin2hex(random_bytes(12));
        }
        return $dir . DIRECTORY_SEPARATOR . $name . '.' . $ext;
    }

    protected function saveFile(string $content, string &$filename = null): string
    {
        if (is_null($filename)) {
            $filename = $this->generateFile('tmp');
        }
        file_put_contents($filename, $content);
        return $filename;
    }

    public function save(string $content, string $filename): bool
    {
        return file_put_contents($filename, $content) !== false;
    }
}