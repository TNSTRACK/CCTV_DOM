// examples/video/video-player-component.tsx
// Patrón estándar para componentes de video con zoom

import React, { useRef, useEffect, useState } from 'react';
import { Box, IconButton, Slider, Paper } from '@mui/material';
import { PlayArrow, Pause, ZoomIn, ZoomOut, Fullscreen } from '@mui/icons-material';
import { TransformWrapper, TransformComponent } from 'react-zoom-pan-pinch';

interface VideoPlayerProps {
  src: string;
  poster?: string;
  onTimeUpdate?: (time: number) => void;
  onMarkerAdd?: (time: number, note: string) => void;
}

export const VideoPlayer: React.FC<VideoPlayerProps> = ({
  src,
  poster,
  onTimeUpdate,
  onMarkerAdd,
}) => {
  const videoRef = useRef<HTMLVideoElement>(null);
  const [isPlaying, setIsPlaying] = useState(false);
  const [currentTime, setCurrentTime] = useState(0);
  const [duration, setDuration] = useState(0);
  const [volume, setVolume] = useState(1);

  // PATRÓN: Control de reproducción con estado sincronizado
  const handlePlayPause = () => {
    if (videoRef.current) {
      if (isPlaying) {
        videoRef.current.pause();
      } else {
        videoRef.current.play();
      }
      setIsPlaying(!isPlaying);
    }
  };

  // PATRÓN: Navegación temporal con validación
  const handleTimeChange = (newTime: number) => {
    if (videoRef.current) {
      videoRef.current.currentTime = newTime;
      setCurrentTime(newTime);
      onTimeUpdate?.(newTime);
    }
  };

  // PATRÓN: Event listeners para estado de video
  useEffect(() => {
    const video = videoRef.current;
    if (!video) return;

    const updateTime = () => setCurrentTime(video.currentTime);
    const updateDuration = () => setDuration(video.duration);
    const handleLoadedData = () => {
      setDuration(video.duration);
      setCurrentTime(0);
    };

    video.addEventListener('timeupdate', updateTime);
    video.addEventListener('loadedmetadata', updateDuration);
    video.addEventListener('loadeddata', handleLoadedData);
    video.addEventListener('play', () => setIsPlaying(true));
    video.addEventListener('pause', () => setIsPlaying(false));

    return () => {
      video.removeEventListener('timeupdate', updateTime);
      video.removeEventListener('loadedmetadata', updateDuration);
      video.removeEventListener('loadeddata', handleLoadedData);
      video.removeEventListener('play', () => setIsPlaying(true));
      video.removeEventListener('pause', () => setIsPlaying(false));
    };
  }, [src]);

  return (
    <Paper elevation={3} sx={{ overflow: 'hidden' }}>
      {/* PATRÓN: Zona de video con zoom y pan */}
      <TransformWrapper
        initialScale={1}
        minScale={1}
        maxScale={10}
        wheel={{ step: 0.1 }}
        panning={{ disabled: false }}
      >
        <TransformComponent>
          <video
            ref={videoRef}
            src={src}
            poster={poster}
            style={{
              width: '100%',
              height: 'auto',
              maxHeight: '70vh',
              backgroundColor: '#000',
            }}
          />
        </TransformComponent>
      </TransformWrapper>

      {/* PATRÓN: Controles personalizados con MUI */}
      <Box sx={{ p: 2, backgroundColor: 'grey.100' }}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mb: 2 }}>
          <IconButton onClick={handlePlayPause} color="primary">
            {isPlaying ? <Pause /> : <PlayArrow />}
          </IconButton>
          
          <Box sx={{ flex: 1, mx: 2 }}>
            <Slider
              value={currentTime}
              max={duration}
              onChange={(_, value) => handleTimeChange(value as number)}
              size="small"
              sx={{ color: 'primary.main' }}
            />
          </Box>
          
          <Box sx={{ minWidth: 80, fontSize: '0.875rem' }}>
            {formatTime(currentTime)} / {formatTime(duration)}
          </Box>
        </Box>

        <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, minWidth: 120 }}>
            <span style={{ fontSize: '0.875rem' }}>Volumen:</span>
            <Slider
              value={volume}
              min={0}
              max={1}
              step={0.1}
              onChange={(_, value) => {
                const newVolume = value as number;
                setVolume(newVolume);
                if (videoRef.current) {
                  videoRef.current.volume = newVolume;
                }
              }}
              size="small"
              sx={{ width: 80 }}
            />
          </Box>
          
          <IconButton size="small" title="Zoom In">
            <ZoomIn />
          </IconButton>
          
          <IconButton size="small" title="Zoom Out">
            <ZoomOut />
          </IconButton>
          
          <IconButton size="small" title="Pantalla Completa">
            <Fullscreen />
          </IconButton>
        </Box>
      </Box>
    </Paper>
  );
};

// PATRÓN: Función utilitaria para formateo de tiempo
const formatTime = (seconds: number): string => {
  const hrs = Math.floor(seconds / 3600);
  const mins = Math.floor((seconds % 3600) / 60);
  const secs = Math.floor(seconds % 60);
  
  if (hrs > 0) {
    return `${hrs}:${mins.toString().padStart(2, '0')}:${secs.toString().padStart(2, '0')}`;
  }
  return `${mins}:${secs.toString().padStart(2, '0')}`;
};