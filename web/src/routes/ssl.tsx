import React from "react";
import { PageShell } from "@/components/page-shell";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { ConfirmDialog } from "@/components/confirm-dialog";
import { EmptyState, ErrorNote, FieldList, FieldRow, LoadingCard } from "@/components/data-ui";
import {
  useCertificates, useDeleteCertificate, useProfile, usePutCertificate,
} from "@/queries/admin";
import { can } from "@/lib/rbac";
import { formatError } from "@/helpers/util";
import { toast } from "sonner";
import type { CertificateView } from "@/lib/types";
import { Pencil, Plus, ShieldCheck, Trash2 } from "lucide-react";

/**
 * Certificate definitions, written through the projection.
 *
 * The view deliberately has no `tls_key` — the API reports `has_tls_key` instead, so a UI
 * can show that a key exists without ever holding one. When a cert is created or edited,
 * the private key is *written* but never read back: the field is write-only at the
 * boundary, which is what keeps this page from becoming a key-exfiltration surface.
 */
export default function Ssl() {
  const profileQuery = useProfile();
  const certificates = useCertificates();
  const putCertificate = usePutCertificate();
  const deleteCertificate = useDeleteCertificate();
  const canEdit = can(profileQuery.data?.data, "edit_certificate");

  const [editing, setEditing] = React.useState<string | null>(null);
  const [deleting, setDeleting] = React.useState<string | null>(null);

  const names = Object.keys(certificates.data?.data ?? {}).sort();
  const target = editing ? (certificates.data?.data ?? {})[editing] : undefined;

  return (
    <PageShell
      title="Certificates"
      eyebrow="Traffic · ssl"
      description="Certificate definitions — a PEM chain or an ACME issuer. Private keys are write-only: set here, never returned by the API."
      actions={
        canEdit && (
          <Button size="sm" onClick={() => setEditing("*new*")}>
            <Plus className="size-4" /> New certificate
          </Button>
        )
      }
    >
      {certificates.isPending ? (
        <LoadingCard />
      ) : certificates.isError ? (
        <ErrorNote message={formatError(certificates.error)} />
      ) : editing ? (
        <CertificateEditor
          isNew={editing === "*new*"}
          name={editing === "*new*" ? "" : editing}
          certificate={target}
          readOnly={!canEdit}
          saving={putCertificate.isPending}
          onClose={() => setEditing(null)}
          onSave={(draft) => {
            putCertificate.mutate(
              { name: draft.name, body: draft.certificate },
              {
                onSuccess: () => {
                  toast.success(`Certificate ${draft.name} saved`);
                  setEditing(null);
                },
                onError: (e) => toast.error("Save failed", { description: formatError(e) }),
              },
            );
          }}
        />
      ) : (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Configured certificates</CardTitle>
            <CardDescription>{names.length} definition{names.length === 1 ? "" : "s"}</CardDescription>
          </CardHeader>
          <CardContent>
            {names.length === 0 ? (
              <EmptyState
                title="No certificates"
                hint="A domain that serves TLS needs a certificate — either a PEM pair or an ACME issuer that produces one."
              />
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Name</TableHead>
                    <TableHead>Domains</TableHead>
                    <TableHead>Source</TableHead>
                    <TableHead>Key</TableHead>
                    <TableHead className="text-right">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {names.map((name) => {
                    const cert = (certificates.data?.data ?? {})[name];
                    return (
                      <TableRow key={name}>
                        <TableCell className="font-medium">{name}</TableCell>
                        <TableCell>{cert?.domains.join(", ")}</TableCell>
                        <TableCell>
                          {cert?.acme ? (
                            <Badge variant="outline">ACME · {cert.acme}</Badge>
                          ) : cert?.tls_cert ? (
                            <Badge variant="secondary">PEM</Badge>
                          ) : (
                            "—"
                          )}
                        </TableCell>
                        <TableCell>
                          {cert?.has_tls_key ? (
                            <Badge variant="outline">key set</Badge>
                          ) : (
                            <span className="text-muted-foreground">—</span>
                          )}
                        </TableCell>
                        <TableCell className="text-right">
                          <Button size="icon" variant="ghost" onClick={() => setEditing(name)}>
                            <Pencil className="size-4" />
                          </Button>
                          {canEdit && (
                            <Button
                              size="icon"
                              variant="ghost"
                              onClick={() => setDeleting(name)}
                            >
                              <Trash2 className="size-4" />
                            </Button>
                          )}
                        </TableCell>
                      </TableRow>
                    );
                  })}
                </TableBody>
              </Table>
            )}
          </CardContent>
        </Card>
      )}

      <ConfirmDialog
        open={deleting !== null}
        onOpenChange={(open) => !open && setDeleting(null)}
        title="Delete certificate"
        description={
          <>
            This removes the certificate{" "}
            <span className="machine font-semibold">{deleting}</span>. A listener or domain
            still referencing it will fail the next handshake.
          </>
        }
        confirmText={deleting ?? ""}
        confirmLabel="Delete"
        busy={deleteCertificate.isPending}
        onConfirm={() => {
          if (!deleting) return;
          deleteCertificate.mutate(deleting, {
            onSuccess: () => {
              toast.success(`Certificate ${deleting} deleted`);
              setDeleting(null);
            },
            onError: (e) => toast.error("Delete failed", { description: formatError(e) }),
          });
        }}
      />
    </PageShell>
  );
}

function CertificateEditor({
  isNew,
  name,
  certificate,
  readOnly,
  saving,
  onClose,
  onSave,
}: {
  isNew: boolean;
  name: string;
  certificate?: CertificateView;
  readOnly: boolean;
  saving: boolean;
  onClose: () => void;
  onSave: (draft: { name: string; certificate: Record<string, unknown> }) => void;
}) {
  const [draftName, setDraftName] = React.useState(name);
  const [domains, setDomains] = React.useState(certificate?.domains.join(", ") ?? "");
  const [tlsCert, setTlsCert] = React.useState(certificate?.tls_cert ?? "");
  const [tlsKey, setTlsKey] = React.useState("");
  const [acme, setAcme] = React.useState(certificate?.acme ?? "");
  const [remark, setRemark] = React.useState(certificate?.remark ?? "");

  const save = () => {
    onSave({
      name: draftName,
      certificate: {
        domains: domains.split(",").map((d) => d.trim()).filter(Boolean),
        tls_cert: tlsCert || undefined,
        // The key is write-only: sent when the operator supplies one, never read back. An
        // empty field leaves the stored key untouched — the API carries the existing key
        // forward when this is absent, so editing a cert does not wipe its key.
        tls_key: tlsKey || undefined,
        acme: acme || undefined,
        remark: remark || undefined,
      },
    });
  };

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader>
          <CardTitle className="text-base">{isNew ? "New certificate" : name}</CardTitle>
          <CardDescription>
            {isNew
              ? "Provide either a PEM chain + key, or an ACME issuer — exactly one of the two."
              : "Editing the certificate. The private key is write-only: leave it blank to keep the stored one."}
          </CardDescription>
        </CardHeader>
        <CardContent>
          <FieldList>
            {isNew && (
              <FieldRow label="Name">
                <Input
                  value={draftName}
                  onChange={(e) => setDraftName(e.target.value)}
                  placeholder="edge"
                  className="machine max-w-xs"
                  readOnly={readOnly}
                />
              </FieldRow>
            )}
            <FieldRow label="Domains">
              <Input
                value={domains}
                onChange={(e) => setDomains(e.target.value)}
                placeholder="example.com, *.example.com"
                className="machine"
                readOnly={readOnly}
              />
            </FieldRow>
            <FieldRow label="ACME issuer">
              <Input
                value={acme}
                onChange={(e) => setAcme(e.target.value)}
                placeholder="lets_encrypt (or leave blank for PEM)"
                className="machine max-w-xs"
                readOnly={readOnly}
              />
            </FieldRow>
            <FieldRow label="PEM chain">
              <Textarea
                value={tlsCert}
                onChange={(e) => setTlsCert(e.target.value)}
                placeholder={"-----BEGIN CERTIFICATE-----\n…"}
                className="machine min-h-24 font-mono text-xs"
                readOnly={readOnly}
              />
            </FieldRow>
            {!readOnly && (
              <FieldRow label="Private key">
                <Textarea
                  value={tlsKey}
                  onChange={(e) => setTlsKey(e.target.value)}
                  placeholder={
                    certificate?.has_tls_key
                      ? "Leave blank to keep the stored key"
                      : "-----BEGIN PRIVATE KEY-----\n…"
                  }
                  className="machine min-h-24 font-mono text-xs"
                  autoComplete="off"
                />
                {certificate?.has_tls_key && (
                  <p className="mt-1 text-xs text-muted-foreground">
                    A key is already stored — it is write-only, so this field stays empty.
                  </p>
                )}
              </FieldRow>
            )}
            <FieldRow label="Remark">
              <Input
                value={remark}
                onChange={(e) => setRemark(e.target.value)}
                placeholder="optional"
                className="machine max-w-md"
                readOnly={readOnly}
              />
            </FieldRow>
          </FieldList>
        </CardContent>
      </Card>

      {!readOnly && (
        <div className="flex items-center gap-2">
          <Button onClick={save} disabled={saving}>
            <ShieldCheck className="size-4" />
            {saving ? "Saving…" : "Save certificate"}
          </Button>
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
        </div>
      )}
    </div>
  );
}
