// examples/forms/metadata-form-component.tsx
// Patrón estándar para formularios con validación

import React from 'react';
import { useForm, Controller } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import {
  Box,
  TextField,
  Button,
  Autocomplete,
  Grid,
  Paper,
  Typography,
  Alert,
} from '@mui/material';
import { DatePicker } from '@mui/x-date-pickers/DatePicker';
import { useMutation, useQuery } from '@tanstack/react-query';

// PATRÓN: Schema de validación con Zod
const metadataSchema = z.object({
  companyId: z.string().min(1, 'Empresa requerida'),
  guideNumber: z.string().min(1, 'Número de guía requerido'),
  guideDate: z.date({ required_error: 'Fecha requerida' }),
  cargoDescription: z.string().min(1, 'Descripción requerida'),
  workOrder1: z.string().min(1, 'Orden de trabajo requerida'),
  workOrder2: z.string().optional(),
  receptionistId: z.string().min(1, 'Recepcionista requerido'),
});

type MetadataFormData = z.infer<typeof metadataSchema>;

interface MetadataFormProps {
  eventId: string;
  onSuccess: () => void;
  initialData?: Partial<MetadataFormData>;
}

export const MetadataForm: React.FC<MetadataFormProps> = ({
  eventId,
  onSuccess,
  initialData,
}) => {
  // PATRÓN: Configuración de React Hook Form con Zod
  const {
    control,
    handleSubmit,
    formState: { errors, isSubmitting },
    reset,
  } = useForm<MetadataFormData>({
    resolver: zodResolver(metadataSchema),
    defaultValues: {
      companyId: '',
      guideNumber: '',
      guideDate: null,
      cargoDescription: '',
      workOrder1: '',
      workOrder2: '',
      receptionistId: '',
      ...initialData,
    },
  });

  // PATRÓN: Queries para datos de formulario
  const { data: companies } = useQuery({
    queryKey: ['companies'],
    queryFn: () => fetch('/api/companies').then(res => res.json()),
  });

  const { data: users } = useQuery({
    queryKey: ['users', 'receptionists'],
    queryFn: () => fetch('/api/users?role=CLIENT_USER').then(res => res.json()),
  });

  // PATRÓN: Mutation para envío de formulario
  const addMetadataMutation = useMutation({
    mutationFn: (data: MetadataFormData) =>
      fetch(`/api/events/${eventId}/metadata`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data),
      }),
    onSuccess: () => {
      reset();
      onSuccess();
    },
  });

  const onSubmit = (data: MetadataFormData) => {
    addMetadataMutation.mutate(data);
  };

  return (
    <Paper elevation={2} sx={{ p: 3 }}>
      <Typography variant="h6" gutterBottom>
        Agregar Metadatos del Evento
      </Typography>

      {addMetadataMutation.error && (
        <Alert severity="error" sx={{ mb: 2 }}>
          Error al guardar metadatos. Intente nuevamente.
        </Alert>
      )}

      <Box component="form" onSubmit={handleSubmit(onSubmit)}>
        <Grid container spacing={2}>
          {/* PATRÓN: Autocomplete con datos remotos */}
          <Grid item xs={12} md={6}>
            <Controller
              name="companyId"
              control={control}
              render={({ field }) => (
                <Autocomplete
                  options={companies || []}
                  getOptionLabel={(option) => option.name}
                  value={companies?.find(c => c.id === field.value) || null}
                  onChange={(_, value) => field.onChange(value?.id || '')}
                  renderInput={(params) => (
                    <TextField
                      {...params}
                      label="Empresa"
                      error={!!errors.companyId}
                      helperText={errors.companyId?.message}
                      required
                    />
                  )}
                />
              )}
            />
          </Grid>

          {/* PATRÓN: Campo de texto con validación */}
          <Grid item xs={12} md={6}>
            <Controller
              name="guideNumber"
              control={control}
              render={({ field }) => (
                <TextField
                  {...field}
                  label="Número de Guía de Despacho"
                  error={!!errors.guideNumber}
                  helperText={errors.guideNumber?.message}
                  required
                  fullWidth
                />
              )}
            />
          </Grid>

          <Grid item xs={12}>
            <Box sx={{ display: 'flex', gap: 2, justifyContent: 'flex-end' }}>
              <Button
                type="button"
                variant="outlined"
                onClick={() => reset()}
                disabled={isSubmitting}
              >
                Limpiar
              </Button>
              <Button
                type="submit"
                variant="contained"
                disabled={isSubmitting}
              >
                Guardar Metadatos
              </Button>
            </Box>
          </Grid>
        </Grid>
      </Box>
    </Paper>
  );
};