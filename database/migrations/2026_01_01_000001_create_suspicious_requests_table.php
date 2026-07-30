<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('suspicious_requests', function (Blueprint $table) {
            $table->id();
            $table->string('ip', 45);
            $table->text('url');
            $table->string('method', 10);
            $table->text('user_agent')->nullable();
            $table->text('referer')->nullable();
            $table->smallInteger('status_code');
            $table->timestamps();

            $table->index('ip');
            $table->index('created_at');
            $table->index(['ip', 'status_code']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('suspicious_requests');
    }
};
